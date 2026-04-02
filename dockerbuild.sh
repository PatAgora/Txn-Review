#!/usr/bin/env zsh
set -e

# Default profile (can be overridden by the environment)
export AWS_PROFILE=${AWS_PROFILE:-agora}

# Selection menus
environments=(dev test demo production)
codenames=(gnosis praxis cortex neuron synapse noesis)

REGION="eu-west-2"
ACCOUNT="116981762688"
REPO="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/scrutinise/transaction"
IMAGE_NAME="scrutinise/transaction"

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found in PATH" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker not found in PATH" >&2; exit 1; }

echo "Select deployment environment:"
PS3="Choose environment (1-${#environments[@]}): "
select env in "${environments[@]}"; do
  if [[ -n "$env" ]]; then
    break
  fi
  echo "Invalid selection. Try again."
done

echo "Select codename:"
PS3="Choose codename (1-${#codenames[@]}): "
select code in "${codenames[@]}"; do
  if [[ -n "$code" ]]; then
    break
  fi
  echo "Invalid selection. Try again."
done

TAG_SUFFIX="${env}-${code}"

echo "Logging into ECR (${REGION})..."
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"

echo "Building Docker image (linux/amd64)..."
docker build --no-cache --platform linux/amd64 -t "${IMAGE_NAME}:latest" -f dockerfile/Dockerfile .

tag="${REPO}:${TAG_SUFFIX}"
echo "Tagging ${IMAGE_NAME}:latest -> ${tag}"
docker tag "${IMAGE_NAME}:latest" "${tag}"
echo "Pushing ${tag}"
docker push "${tag}"

echo "All done."
