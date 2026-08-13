# Reproducible environment for the experiment pipeline (RQ1 ground-truth checking and
# run-llm-summarization, which needs the LLM/Bedrock deps installed below).
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

# Python deps for run_experiment.py and argot-summarize (the LLM agent used by
# run-llm-summarization): installing python/ in editable mode pulls in its requirements.txt
# (pyyaml, rich, plus the LLM/Bedrock deps: strands-agents, mcp, boto3) and registers the
# argot-summarize console script.
WORKDIR /usr/src/app
RUN python3 -m venv experiment/.venv && \
    . experiment/.venv/bin/activate && \
    pip install --no-cache-dir -e python/
# The entrypoint below runs .venv/bin/python3 directly rather than activating the venv, so
# argot-summarize (spawned as a subprocess by run_experiment.py) needs the venv's bin/ on PATH
# to be found; subprocess.Popen inherits this process's environment, not a shell that ran
# `activate`.
ENV PATH="/usr/src/app/experiment/.venv/bin:${PATH}"

WORKDIR /usr/src/app/experiment

ENTRYPOINT [".venv/bin/python3", "run_experiment.py"]
