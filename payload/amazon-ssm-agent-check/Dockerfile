# Build me from root of this repo:
# docker build -t amazon-ssm-agent-check -f payload/amazon-ssm-agent-check/Dockerfile .
FROM golang:1.24

WORKDIR /usr/src/app

# Setup some dependencies
RUN apt update && apt install -y python3-venv python3-pip

# Copy go mod and cache dependencies
COPY go.mod go.sum ./
RUN go env -w GOPROXY=direct
RUN go mod download

# Build Argot
COPY . .
RUN go build -o bin/argot ./cmd/argot/main.go
RUN go install github.com/awslabs/ar-go-tools/cmd/argot

# Install Python dependencies:
## Remove any leftover .venv
RUN rm -rf .venv
## Create venv
RUN python3 -m venv .venv
## Get pip deps
RUN . .venv/bin/activate && \
    pip install -r payload/amazon-ssm-agent-check/requirements.txt

# Clean & Clone the Amazon-ssm-agent
RUN rm -rf amazon-ssm-agent && \
    git clone https://github.com/aws/amazon-ssm-agent.git && \
    mkdir -p amazon-ssm-agent/logs/argot

ENTRYPOINT [ "/bin/sh" ]
