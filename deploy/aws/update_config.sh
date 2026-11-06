#!/usr/bin/env bash
# Operator runbook script: add the client-portal route to the Caddyfile of an
# EXISTING ESET SOC Lite instance, through SSM Run Command (no SSH).
#
# Why this exists: the Caddyfile is written by the stack's UserData, which runs
# only on first boot. Changing cloudformation.yaml therefore does NOT reach an
# instance that is already running. New stacks get the route automatically.
#
#   deploy/aws/update_config.sh STACK_NAME [--client-cidr CIDR] [--yes]
#
#   STACK_NAME           CloudFormation stack, e.g. eset-soc-lite-poc
#   --client-cidr CIDR   who may reach /client (default 0.0.0.0/0; the portal has
#                        its own login). Use the same value as the stack's
#                        ClientCidr parameter.
#   --yes                actually apply. Without it this is a DRY RUN: it only
#                        reads the current Caddyfile from the instance and prints
#                        what would change. Nothing on the instance is modified.
#
# What the remote step does (all idempotent):
#   1. Exits successfully, changing nothing, if the Caddyfile already contains
#      the "client portal" marker.
#   2. Backs up /opt/soc-lite/Caddyfile to /opt/soc-lite/Caddyfile.bak.<UTC time>.
#   3. Inserts the /client handler immediately BEFORE the "@admin remote_ip"
#      line (so it precedes the admin catch-all). Aborts if that line is absent.
#   4. Validates the candidate file with `caddy validate` (using the local
#      caddy:2 image) before touching the live file.
#   5. Writes the live file IN PLACE (same inode; Caddy's container bind-mounts
#      this single file, so replacing it with mv would leave Caddy on the old one).
#   6. Reloads Caddy with `caddy reload` (no downtime). If the reload fails the
#      backup is restored and the failure is reported.
#
# Prerequisites: aws CLI v2 with credentials for the target account, AWS_REGION
# set, and the instance reachable by SSM (it is, if release.sh works).
# Roll back by hand: copy the .bak file over /opt/soc-lite/Caddyfile and run
#   docker exec caddy caddy reload --config /etc/caddy/Caddyfile
set -euo pipefail

REGION="${AWS_REGION:?set AWS_REGION, e.g. ap-northeast-1}"
STACK=""
CLIENT_CIDR="0.0.0.0/0"
APPLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --yes) APPLY=1 ;;
    --client-cidr) CLIENT_CIDR="${2:?--client-cidr needs a value}"; shift ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) STACK="$1" ;;
  esac
  shift
done
[ -n "$STACK" ] || { echo "usage: $0 STACK_NAME [--client-cidr CIDR] [--yes]" >&2; exit 2; }

# Same shape the template enforces for ClientCidr. Also keeps the value safe to
# embed in the remote script (digits, dots and one slash only).
if ! [[ "$CLIENT_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
  echo "invalid --client-cidr: $CLIENT_CIDR (expected a.b.c.d/nn)" >&2
  exit 2
fi

INSTANCE=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text)
[ -n "$INSTANCE" ] && [ "$INSTANCE" != "None" ] || { echo "no InstanceId output on stack $STACK" >&2; exit 1; }

echo "Stack:       $STACK"
echo "Instance:    $INSTANCE ($REGION)"
echo "Client CIDR: $CLIENT_CIDR"
echo
echo "Will add this handler to /opt/soc-lite/Caddyfile, before the '@admin' handler:"
cat <<EOF
  # Client portal ...
  @client {
    path /client /client/*
    remote_ip $CLIENT_CIDR
  }
  handle @client {
    reverse_proxy soc-lite:8000
  }
EOF
echo
if [ "$APPLY" -ne 1 ]; then
  echo "DRY RUN: nothing was changed on the instance. Re-run with --yes to apply."
  MODE=dryrun
else
  MODE=apply
fi

# The remote script. Quoted heredoc: nothing here is expanded locally; the two
# values it needs are prepended as variable assignments below.
read -r -d '' REMOTE_BODY <<'REMOTE' || true
set -euo pipefail
CF=/opt/soc-lite/Caddyfile
MARK='# Client portal'
[ -f "$CF" ] || { echo "ERROR: $CF not found"; exit 1; }
if grep -q "^[[:space:]]*$MARK" "$CF"; then
  echo "Caddyfile already has the client portal handler; nothing to do."
  exit 0
fi
grep -q '^[[:space:]]*@admin remote_ip' "$CF" || { echo "ERROR: no '@admin remote_ip' line in $CF; refusing to guess where to insert"; exit 1; }
SNIP=$(mktemp); NEW=$(mktemp)
cat > "$SNIP" <<SNIPEOF
  $MARK (page, /client/assets/*, /client/api/*). Own login; the app serves its
  # assets, so no /static exposure. Production needs DASHBOARD_ACCESS_KEY >= 16
  # chars or the app refuses to enable the portal. Never add engineering paths here.
  @client {
    path /client /client/*
    remote_ip $CLIENT_CIDR
  }
  handle @client {
    reverse_proxy soc-lite:8000
  }
SNIPEOF
# Insert before the first @admin line only.
awk -v snip="$SNIP" '
  !done && /^[[:space:]]*@admin remote_ip/ { while ((getline l < snip) > 0) print l; done=1 }
  { print }' "$CF" > "$NEW"
echo "---- diff (current -> new) ----"
diff -u "$CF" "$NEW" || true
echo "-------------------------------"
if [ "$MODE" != apply ]; then
  echo "DRY RUN on instance: no changes made."
  rm -f "$SNIP" "$NEW"
  exit 0
fi
if command -v docker >/dev/null 2>&1; then
  # Validate the candidate with the same Caddy image, before touching the live file.
  docker run --rm -v "$NEW":/etc/caddy/Caddyfile:ro caddy:2 caddy validate --config /etc/caddy/Caddyfile
else
  echo "WARNING: docker not found; skipping caddy validate"
fi
BAK="$CF.bak.$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$CF" "$BAK"
echo "Backup: $BAK"
cat "$NEW" > "$CF"   # in place: keep the inode the caddy container has mounted
if docker exec caddy caddy reload --config /etc/caddy/Caddyfile; then
  echo "Caddy reloaded. Client portal route is live for $CLIENT_CIDR."
else
  echo "ERROR: reload failed; restoring $BAK"
  cat "$BAK" > "$CF"
  docker exec caddy caddy reload --config /etc/caddy/Caddyfile || true
  exit 1
fi
rm -f "$SNIP" "$NEW"
REMOTE

SCRIPT="MODE=$MODE
CLIENT_CIDR=$CLIENT_CIDR
$REMOTE_BODY"
# base64 keeps the script intact through SSM's JSON parameter quoting.
B64=$(printf '%s\n' "$SCRIPT" | base64 | tr -d '\n')

COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript \
  --comment "eset-soc-lite client portal caddy route ($MODE)" \
  --parameters "commands=[\"echo $B64 | base64 -d | bash\"]" \
  --query Command.CommandId --output text)
echo "SSM command: $COMMAND_ID (waiting...)"
aws ssm wait command-executed --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE" || true
aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE" \
  --query "{Status:Status,Output:StandardOutputContent,Error:StandardErrorContent}" --output json
STATUS=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE" \
  --query Status --output text)
[ "$STATUS" = "Success" ] || { echo "Remote step did not succeed ($STATUS)" >&2; exit 1; }
if [ "$MODE" = apply ]; then
  echo "Done. Verify: curl -s -o /dev/null -w '%{http_code}\n' https://<DomainName>/client/  (200/302, not 403)"
  echo "and that https://<DomainName>/dashboard is still 403 from outside AdminCidr."
fi
