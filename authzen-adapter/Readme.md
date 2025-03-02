Below is a straightforward set of commands to build your authzen-pdp image from a Dockerfile, tag it, and push it to the existing ECR repository (586794481579.dkr.ecr.ap-southeast-2.amazonaws.com/idpartners/authzen-pdp) referenced in your CloudFormation template. You can adapt the same approach for any other images (like pingauthorize) you need to build and push.

1. Ensure You Have a Dockerfile

Make sure you have a Dockerfile in the root of your Go project (the one you want to run on ECS Fargate). For example:

# Stage 1: Build the Go application
FROM golang:1.19-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build for Linux, x86_64 (amd64) for ECS Fargate
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /authzen-pdp .

# Stage 2: Create a minimal Alpine image with the compiled binary
FROM alpine:latest
WORKDIR /root
COPY --from=builder /authzen-pdp .
EXPOSE 8080
ENTRYPOINT ["./authzen-pdp"]

Adjust the Go version, base images, and any additional commands as you need.

2. Build the Docker Image Locally

From your project directory (where the Dockerfile resides):

# Build your authzen-pdp image
docker build -t authzen-pdp:latest .

This produces a local Docker image named authzen-pdp:latest.

3. Log In to ECR

Use the AWS CLI to authenticate Docker to your ECR registry. Since your region is ap-southeast-2 and your account ID is 586794481579, run:

aws ecr get-login-password --region ap-southeast-2 \
| docker login \
  --username AWS \
  --password-stdin 586794481579.dkr.ecr.ap-southeast-2.amazonaws.com

You should see Login Succeeded if it worked.

4. Tag Your Local Image for ECR

Now tag your locally built image (authzen-pdp:latest) to match the ECR repository address shown in your CloudFormation template:

docker tag authzen-pdp:latest \
  586794481579.dkr.ecr.ap-southeast-2.amazonaws.com/idpartners/authzen-pdp:latest

5. Push the Image to ECR

Finally, push that newly tagged image to your ECR repo:

docker push 586794481579.dkr.ecr.ap-southeast-2.amazonaws.com/idpartners/authzen-pdp:latest

Once completed, your image is stored in ECR at:

586794481579.dkr.ecr.ap-southeast-2.amazonaws.com/idpartners/authzen-pdp:latest

Your ECS Task Definition (in the CloudFormation) references this same ECR image URL, so when ECS Fargate starts the task, it will pull this image from ECR.

That’s It!

Whenever you update your code, repeat:
	1.	docker build
	2.	docker tag
	3.	docker push

…and ECS will pull the latest image upon deploying or restarting your service.