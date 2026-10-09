# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "${VERSION:+-X github.com/brodyhoskins/mailcached/internal/version.Version=$VERSION}" \
      -o /out/ ./cmd/...

FROM alpine:3
RUN apk add --no-cache ca-certificates libcap && \
    addgroup -S mailcached && \
    adduser -S -D -H -G mailcached -h /var/cache/mailcached -s /sbin/nologin mailcached && \
    install -d -o mailcached -g mailcached -m 0700 /var/cache/mailcached

COPY --from=build /out/ /usr/local/bin/
RUN setcap cap_net_bind_service=+ep /usr/local/bin/mailcached && apk del libcap

USER mailcached
ENV CACHE_DIRECTORY=/var/cache/mailcached
VOLUME ["/var/cache/mailcached"]
EXPOSE 993 465
ENTRYPOINT ["mailcached", "-config", "/etc/mailcached/mailcached.yaml"]
