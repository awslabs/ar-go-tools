# Reproducible environment for the checker-precision (RQ1) ground-truth experiment.
#
# Build from anywhere (no build context files are needed beyond this file itself):
#   docker build -t argot-experiment -f experiment/Dockerfile experiment
#   docker run --rm -v $(pwd)/results:/usr/src/app/experiment/results argot-experiment <command...>
#
# Clones ar-go-tools at the rework-evaluation branch and each of the 4 external target repos
# at the pinned commit recorded in run_experiment.py's REPOS dict (kept in sync manually --
# if you update a pinned commit there, update the corresponding git checkout below too). The
# 5th target repo, "sample", is a small local Go program tracked directly in ar-go-tools
# itself, so it needs no separate clone.
# The 5 target repos have their own go.mod requirements independent of argot's own; badger's
# go.mod requires toolchain go1.25.0, the strictest of the 5, so the base image must be at
# least that new.
FROM golang:1.25

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y python3-venv python3-pip git

# Clone ar-go-tools itself.
RUN git clone --branch rework-evaluation --single-branch \
    https://github.com/awslabs/ar-go-tools.git .

# Build and install argot.
RUN go mod download && \
    go build -o bin/argot ./cmd/argot/main.go && \
    go install github.com/awslabs/ar-go-tools/cmd/argot
ENV PATH="/root/go/bin:${PATH}"

# Clone the 4 external target repos at their pinned commits (see run_experiment.py's REPOS).
WORKDIR /usr/src/app/payload/public-repos-checks
RUN git clone https://github.com/aws/amazon-ssm-agent.git amazon-ssm-agent && \
    git -C amazon-ssm-agent checkout ef5df636f7035bb1e3e325fab519379715678033
RUN git clone https://github.com/dgraph-io/badger.git badger && \
    git -C badger checkout a700dc3b6332e2351674f34f841233541568f782
RUN git clone https://github.com/o1egl/govatar.git govatar && \
    git -C govatar checkout 31618c34a7ae828c61629e022b1654e4ec552628
RUN git clone https://github.com/prometheus/client_golang.git prometheus && \
    git -C prometheus checkout 7ba246a648ca4e294ca008d95b6fcc8df2f9c255

# Minimal Python deps for run_experiment.py (pyyaml + rich only -- no LLM/Bedrock deps needed
# for the ground-truth RQ1 pipeline).
WORKDIR /usr/src/app
RUN python3 -m venv experiment/.venv && \
    . experiment/.venv/bin/activate && \
    pip install --no-cache-dir pyyaml rich

WORKDIR /usr/src/app/experiment

ENTRYPOINT [".venv/bin/python3", "run_experiment.py"]
