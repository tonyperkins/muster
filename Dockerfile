# Multi-stage build. The final image is itself a demonstration of the standard
# muster enforces: a static, non-root, shell-less, package-manager-less image.

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 yields a fully static binary with no libc dependency, which is
# the entire reason muster is written in Go: drop-in distribution anywhere.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /muster .

FROM cgr.dev/chainguard/static:latest
COPY --from=build /muster /usr/bin/muster
USER nonroot
ENTRYPOINT ["/usr/bin/muster"]
