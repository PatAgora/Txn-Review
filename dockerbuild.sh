#!/usr/bin/env zsh
set -e

# Default profile (can be overridden by the environment)
export AWS_PROFILE=${AWS_PROFILE:-agora}

# Environments to tag/push to
environments=(dev demo)

REGION="eu-west-2"
ACCOUNT="116981762688"
REPO="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/scrutinise/transaction"
IMAGE_NAME="scrutinise/transaction"

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found in PATH" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker not found in PATH" >&2; exit 1; }

echo "Logging into ECR (${REGION})..."
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"

echo "Building Docker image (linux/amd64)..."
docker build --no-cache --platform linux/amd64 -t "${IMAGE_NAME}:latest" -f dockerfile/Dockerfile .

for env in "${environments[@]}"; do
  tag="${REPO}:${env}"
  echo "Tagging ${IMAGE_NAME}:latest -> ${tag}"
  docker tag "${IMAGE_NAME}:latest" "${tag}"
  echo "Pushing ${tag}"
  docker push "${tag}"
done

echo "All done."