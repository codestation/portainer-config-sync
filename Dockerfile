FROM golang:1.25-alpine AS builder

ARG CI_COMMIT_TAG
ARG GOPROXY
ENV GOPROXY=${GOPROXY}

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src/

RUN set -ex; \
    CGO_ENABLED=0 go build -o release/portainer-config-sync \
    -trimpath \
    -ldflags "-w -s \
    -X main.Tag=${CI_COMMIT_TAG}"

FROM alpine:3.22
LABEL maintainer="codestation <codestation@megpoid.dev>"

ENV CONFIG_PATH=/config.yaml

RUN apk add --no-cache ca-certificates tzdata

RUN set -eux; \
    addgroup -S runner -g 1000; \
    adduser -S runner -G runner -u 1000

COPY --from=builder /src/release/portainer-config-sync /usr/bin/portainer-config-sync

USER runner

CMD ["/usr/bin/portainer-config-sync"]
