# Build from the repository root. This row is written, not built; the
# integrator tries a build only if a container daemon is running here.
# The Go image tag matches go.mod's toolchain. Digest pinning needs the network
# and is left to user row U2, along with the container build and lab run.
FROM golang:1.26.9-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# Copy only the log command and its packages, never operator key directories.
COPY internal/ ./internal/
COPY cmd/norn-log/ ./cmd/norn-log/
RUN CGO_ENABLED=0 go build -trimpath -o /out/norn-log ./cmd/norn-log

FROM alpine:3.22
COPY --from=build /out/norn-log /usr/local/bin/norn-log
# Docker initializes a new named volume with this directory's ownership.
RUN mkdir -p /var/lib/norn-log /etc/norn-log && chown 65532:65532 /var/lib/norn-log
USER 65532:65532
VOLUME ["/var/lib/norn-log"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/norn-log", "-dir", "/var/lib/norn-log", "-key", "/etc/norn-log/log.key", "-trust", "/etc/norn-log/norn.trust", "-listen", "0.0.0.0:8080"]

# The log directory is the only writable mount; no tmpfs is needed. Provision
# log.key and norn.trust outside the image, readable by UID 65532. They are
# read-only mounts, not build inputs. An existing volume also needs that UID.
# After building norn-log:local in U2, run under docker run --read-only:
# docker run --read-only --mount type=volume,src=norn-log,dst=/var/lib/norn-log --mount type=bind,src="$PWD/log.key",dst=/etc/norn-log/log.key,readonly --mount type=bind,src="$PWD/norn.trust",dst=/etc/norn-log/norn.trust,readonly -p 127.0.0.1:8080:8080 norn-log:local
