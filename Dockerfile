# syntax=docker/dockerfile:1
FROM public.ecr.aws/docker/library/golang:1.20-alpine
RUN apk --no-cache add ca-certificates git
RUN apk --no-cache add make
WORKDIR argot
COPY ./ .
ENV GOPROXY=direct
RUN make