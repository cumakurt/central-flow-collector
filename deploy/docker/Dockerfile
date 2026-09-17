FROM golang:1.23 AS build
WORKDIR /src
COPY . .
ARG VERSION=4.0.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X central-flow-collector/internal/buildinfo.Version=${VERSION}" -o /out/flowcollector ./cmd/flowcollector

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/flowcollector /usr/local/bin/flowcollector
COPY config.example.yaml /etc/flowcollector/config.yaml
VOLUME ["/var/lib/flowcollector"]
EXPOSE 8080/tcp 2055/udp 4739/udp 6343/udp
ENTRYPOINT ["/usr/local/bin/flowcollector","run","--config","/etc/flowcollector/config.yaml"]
