# syntax=docker/dockerfile:1
FROM golang:1.19-alpine
RUN apk --no-cache add ca-certificates git
RUN apk --no-cache add make
WORKDIR argot
COPY ./ .
ENV GOPROXY=direct
RUN make