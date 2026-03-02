# Transaction Review - Build and Push Guide

This guide shows how to:
- Download and install AWS CLI
- Configure AWS CLI (keys or SSO) for the `agora` profile
- Build the Docker image for Transaction Review
- Run `dockerbuild.sh` to push to Amazon ECR (eu-west-2)

## Docs
[AWS Cli install and configuration](https://github.com/AgoraConsulting/aws_deployment/blob/main/doc/aws-cli-sso-setup.md)

## Prerequisites
- Docker Desktop (or Docker Engine) installed and running
- Access to AWS account `116981762688` with ECR permissions
- An existing ECR repository: `116981762688.dkr.ecr.eu-west-2.amazonaws.com/scrutinise/transaction`

## Build the Docker Image (manual)

From the `transaction_review` directory:
```bash
docker build --no-cache -t scrutinise/transaction -f dockerfile/Dockerfile .
```

Optionally run locally (if the app exposes a port in the Dockerfile):
```bash
docker run --rm -p 3000:3000 scrutinise/transaction:latest
```

## Use dockerbuild.sh (build + tag + push)

The script logs in to ECR (eu-west-2), builds the image, tags it as `:dev`, and pushes it.

Script location: `transaction_review/dockerbuild.sh`

Make it executable (Linux/WSL/macOS):
```bash
chmod +x dockerbuild.sh
```

Run it:
```bash
./dockerbuild.sh
```

What it does:
- Sets `AWS_PROFILE=agora`
- `aws ecr get-login-password` and `docker login` to the registry
- `docker build` using `dockerfile/Dockerfile`
- `docker tag` to `116981762688.dkr.ecr.eu-west-2.amazonaws.com/scrutinise/transaction:dev`
- `docker tag` to `116981762688.dkr.ecr.eu-west-2.amazonaws.com/scrutinise/transaction:demo`
- `docker tag` to `116981762688.dkr.ecr.eu-west-2.amazonaws.com/scrutinise/transaction:production`
- `docker push` to ECR

## Troubleshooting

- Docker daemon not running:
	- Start Docker Desktop or `sudo service docker start` (Linux)

- `RepositoryNotFoundException` on push:
	- Create the ECR repository first:
		```bash
		aws ecr create-repository \
			--repository-name scrutinise/transaction \
			--region eu-west-2 \
			--profile agora
		```

- `AccessDeniedException` during `docker login` or `push`:
	- Ensure your `agora` profile has ECR permissions (e.g., `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`, `ecr:PutImage`, `ecr:InitiateLayerUpload`, etc.).

- Wrong region or profile:
	- Confirm the script uses `eu-west-2` and `AWS_PROFILE=agora`.

- Verify image in ECR:
	```bash
	aws ecr describe-images \
		--repository-name scrutinise/transaction \
		--region eu-west-2 \
		--profile agora \
		--query 'imageDetails[].imageTags'
	```

## Notes
- If running on Windows PowerShell, execute the script via Git Bash or WSL, or run the commands manually.
- To push a different tag (e.g., `:staging`), adjust the `docker tag` and `docker push` commands accordingly.

