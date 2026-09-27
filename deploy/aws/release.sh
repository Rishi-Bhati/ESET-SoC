#!/usr/bin/env bash
# Build the platform image, push it to ECR, and (optionally) roll it out to a
# running environment through SSM — no SSH, no credentials on the host.
#
#   deploy/aws/release.sh                     # build + push, prints the image URI
#   deploy/aws/release.sh eset-soc-lite-poc   # build + push + roll out to that stack
#
# Needs: docker, aws CLI v2 with credentials for the target account, AWS_REGION set.
set -euo pipefail

REGION="${AWS_REGION:?set AWS_REGION, e.g. ap-northeast-1}"
REPO=eset-soc-lite
STACK="${1:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGISTRY="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
TAG="$(date -u +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo local)"
IMAGE="$REGISTRY/$REPO:$TAG"

aws ecr describe-repositories --region "$REGION" --repository-names "$REPO" >/dev/null 2>&1 || \
  aws ecr create-repository --region "$REGION" --repository-name "$REPO" \
    --image-scanning-configuration scanOnPush=true --image-tag-mutability IMMUTABLE >/dev/null

aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"
docker build --platform linux/amd64 -t "$IMAGE" "$ROOT"
docker push "$IMAGE"
echo "Pushed $IMAGE"

[ -z "$STACK" ] && exit 0

INSTANCE=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text)
echo "Rolling out to $STACK ($INSTANCE)"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript \
  --comment "eset-soc-lite release $TAG" \
  --parameters "commands=[\"echo IMAGE_URI=$IMAGE > /opt/soc-lite/image.env\",\"/opt/soc-lite/run.sh\"]" \
  --query Command.CommandId --output text)
aws ssm wait command-executed --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE" || true
aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE" \
  --query "{Status:Status,Output:StandardOutputContent,Error:StandardErrorContent}" --output json
echo "Note: the stack's ImageUri parameter still names the previous image; update it on the next stack update."
