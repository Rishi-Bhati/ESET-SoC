# Deploying ESET SOC Lite on AWS

One CloudFormation stack per environment (`poc`, `staging`, `prod`), from `deploy/aws/cloudformation.yaml`.

```
ESET PROTECT Cloud ──HTTPS──▶ Elastic IP ─▶ EC2 (Amazon Linux 2023, IMDSv2 only)
                                            ├─ caddy (TLS via Let's Encrypt)
                                            │    /webhook/*, /health  → public (webhook is token-authenticated)
                                            │    everything else      → AdminCidr only, 403 otherwise
                                            └─ soc-lite container (read-only root, no capabilities)
                                                 ├─ /data  → encrypted EBS volume, daily snapshots (14 kept)
                                                 ├─ secrets ← Secrets Manager via the instance role
                                                 └─ stdout → CloudWatch Logs /eset-soc-lite/<env>
Optional: syslog UDP 514 / TCP 601 open to SyslogSourceCidr only.   Admin shell: SSM Session Manager (no SSH).
```

## Why a single EC2 host and not ECS/Fargate (for now)

The platform stores its state in **SQLite** and runs the **syslog listeners inside the API process**. Both assume one long-lived host with a local disk:

- **SQLite:** its WAL mode is not safe on EFS/NFS, so SQLite needs a local disk.
- **Syslog on Fargate:** UDP syslog would need an NLB in front of it.

A single EC2 instance with an EBS volume runs the platform unchanged. It also has the fewest moving parts for a PoC.

To scale out later (for production at volume):

1. Move storage to RDS PostgreSQL.
2. Move the listeners behind an NLB.
3. Run the container on ECS Fargate. The container, the Secrets Manager integration and the configuration carry over as they are.

## Prerequisites

- An AWS account and region. `ap-northeast-1` (Tokyo) is recommended, so data stays in Japan on the AWS side.
- A VPC with a public subnet.
- A DNS name you control, for example `soc-poc.example.com`.
- The admin network range (office or VPN egress).
- Local tools: Docker and AWS CLI v2.
- **OpenAI:** a dedicated project per environment, for example `eset-soc-lite-poc` and `eset-soc-lite-prod`, each with a project-scoped key and a monthly budget limit.

## 1. Build and push the image

```bash
export AWS_REGION=ap-northeast-1
deploy/aws/release.sh
# → Pushed 123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/eset-soc-lite:20260927-0900-abc1234
```

The script creates the ECR repository on first use, with scan-on-push and immutable tags.

## 2. Create the stack

```bash
aws cloudformation deploy --region $AWS_REGION \
  --stack-name eset-soc-lite-poc \
  --template-file deploy/aws/cloudformation.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
      EnvName=poc \
      VpcId=vpc-xxxxxxxx SubnetId=subnet-xxxxxxxx \
      DomainName=soc-poc.example.com \
      AdminCidr=203.0.113.0/24 \
      ImageUri=123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/eset-soc-lite:20260927-0900-abc1234 \
      OpenAIModel=gpt-5-mini \
      EmailApiUrl=https://<mail-worker>/api/send
      # EmailApiUrl blank = email handoff off (alerts still processed and kept in the outbox)
      # SyslogSourceCidr=198.51.100.10/32   # only if using syslog export
```

Then create a DNS **A record** for `DomainName` that points to the `ElasticIp` output.

## 3. Put the real secrets in (never through CloudFormation)

The stack creates two secrets with random placeholder values. **The container refuses to start** until the webhook token is replaced, because `APP_ENV=production` rejects placeholder credentials.

**OpenAI key.** Paste it from the OpenAI project page. `read -s` keeps it out of shell history and the screen:

```bash
read -rs OPENAI_KEY && aws secretsmanager put-secret-value --region $AWS_REGION \
  --secret-id eset-soc-lite/poc/openai-api-key --secret-string "$OPENAI_KEY" && unset OPENAI_KEY
```

**Platform credentials** (one JSON secret):

```bash
python3 - <<'EOF' > /tmp/app-secret.json
import json, secrets
print(json.dumps({
    "ESET_WEBHOOK_AUTH_TOKEN": secrets.token_urlsafe(32),
    "DASHBOARD_ACCESS_KEY": secrets.token_urlsafe(32),
    "EMAIL_API_KEY": "",          # from the ESET Mail service
    "EMAIL_API_SECRET": "",
    "VIRUSTOTAL_API_KEY": "",     # optional; see USE_MOCK_THREAT_INTEL
    "ABUSEIPDB_API_KEY": "",
}))
EOF
aws secretsmanager put-secret-value --region $AWS_REGION \
  --secret-id eset-soc-lite/poc/app --secret-string file:///tmp/app-secret.json
shred -u /tmp/app-secret.json
```

Share the webhook token and dashboard key through your password manager, not by email or chat.

**Restart the container** so it loads the platform credentials. The OpenAI key is read on the first AI call, so it does not need a restart.

```bash
INSTANCE=$(aws cloudformation describe-stacks --stack-name eset-soc-lite-poc \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text)
aws ssm send-command --instance-ids $INSTANCE --document-name AWS-RunShellScript \
  --parameters 'commands=["/opt/soc-lite/run.sh"]'
```

## 4. Verify

1. `curl https://soc-poc.example.com/health` should return `"status": "ok"`, with `ai_provider.status` equal to `configured`.
2. Open the dashboard from the admin network. Go to **Settings → AI Provider** and click **Test connection**. It should report that the model is available, with an OpenAI request ID. **Security posture** should show "AI API key storage: AWS Secrets Manager".
3. Run the PoC cases against the deployment. Each case costs one AI generation.
   ```bash
   python scripts/run_poc_cases.py --url https://soc-poc.example.com \
     --token "$ESET_WEBHOOK_AUTH_TOKEN" --dashboard-key "$DASHBOARD_ACCESS_KEY"
   ```
   The cases go through the real pipeline, so when `EmailApiUrl` is set **configured recipients receive the emails**. Set the recipients to your own team first, in the dashboard under Settings.
4. In ESET PROTECT Cloud, register the `WebhookUrl` output with the header `Authorization: Bearer <ESET_WEBHOOK_AUTH_TOKEN>`, then send a test webhook.

## Operations

| Task | How |
|---|---|
| Deploy a new version | `deploy/aws/release.sh eset-soc-lite-poc` (build, push, then roll out through SSM) |
| Rotate the OpenAI key | Create the new key in the OpenAI project, then run `put-secret-value`. The app picks it up within `SECRET_CACHE_TTL_SECONDS` (5 min), or immediately on the next 401. Then revoke the old key. |
| Rotate the webhook token or dashboard key | Update the `app` secret, restart through SSM (see step 3), and update the token in ESET PROTECT. |
| Shell on the host | `aws ssm start-session --target $INSTANCE` |
| Logs | CloudWatch Logs `/eset-soc-lite/<env>`, streams `soc-lite` and `caddy`. The dashboard's Logs view reads `/data/logs/app.log`. |
| Backups | DLM snapshots of the data volume daily at 18:00 UTC (03:00 JST), 14 kept. On stack deletion the volume is snapshotted, and the secrets are retained. |
| Change model or provider | Update the stack parameter, or edit `/opt/soc-lite/app.env` and run `run.sh`. Record the change; each alert's audit record stores the model that served it. |

## Security summary

- **No SSH and no inbound admin ports.** Administration goes through SSM Session Manager. IMDSv2 is required.
- **Dashboard access:** the dashboard is reachable only from `AdminCidr`, at the proxy, *and* requires `DASHBOARD_ACCESS_KEY`. Only `/webhook/*` and `/health` are public.
- **Separated environments:** each stack's role can read only `eset-soc-lite/<its env>/*`. Each environment uses a separate OpenAI project and key.
- **Encryption at rest:** the EBS volumes and Secrets Manager secrets are encrypted. TLS 1.2+ is used on every hop to the internet: ESET to the platform, and the platform to OpenAI and the mail service.
- **Secrets stay out of storage:** no secrets exist in the image, the template, stack parameters, user data or on disk (`/opt/soc-lite/app.env` holds only secret *names*).
- **Container hardening:** read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, non-root user (UID 10001).
- **Syslog:** closed unless `SyslogSourceCidr` is set. It is then open only to that range, and the app-level `SYSLOG_ALLOWED_SOURCES` is set to the same range.
