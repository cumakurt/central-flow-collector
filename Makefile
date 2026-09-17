APP=flowcollector
VERSION?=4.0.0
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-s -w -X central-flow-collector/internal/buildinfo.Version=$(VERSION) -X central-flow-collector/internal/buildinfo.Commit=$(COMMIT) -X central-flow-collector/internal/buildinfo.BuildTime=$(BUILD_TIME)

.PHONY: build static test test-race vet lint benchmark query-benchmark fuzz package deb rpm clean frontend installer-test release-check sbom
static:
	VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_TIME=$(BUILD_TIME) ./scripts/build-static.sh

build:
	VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_TIME=$(BUILD_TIME) TARGETS=linux/amd64 ./scripts/build-static.sh

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint: vet
	@echo "go vet passed; no external linter dependency required"

frontend:
	@echo "Frontend is dependency-free static TypeScript-free JS/CSS embedded at build time; no external build step required."

benchmark:
	go test -run '^$$' -bench=. -benchmem ./internal/decoder/...

query-benchmark:
	go run ./cmd/querybench -rows 50000 -iterations 5

fuzz:
	@echo "Run targeted fuzzing, e.g. go test ./internal/decoder/netflow5 -fuzz=FuzzDecode -fuzztime=30s"

package: clean
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/flowcollector-linux-amd64 ./cmd/flowcollector
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/flowcollector-linux-arm64 ./cmd/flowcollector
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/flowgen-linux-amd64 ./cmd/flowgen
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/flowgen-linux-arm64 ./cmd/flowgen
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/chbench-linux-amd64 ./cmd/chbench
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/chbench-linux-arm64 ./cmd/chbench
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/flowbench-linux-amd64 ./cmd/flowbench
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/flowbench-linux-arm64 ./cmd/flowbench
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/querybench-linux-amd64 ./cmd/querybench
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/querybench-linux-arm64 ./cmd/querybench
	cp install.sh uninstall.sh config.example.yaml LICENSE NOTICE dist/
	VERSION=$(VERSION) python3 scripts/generate-sbom.py
	cd dist && sha256sum flowcollector-linux-* flowgen-linux-* chbench-linux-* flowbench-linux-* querybench-linux-* SBOM.*.json LICENSE NOTICE > checksums.txt

deb:
	VERSION=$(VERSION) ./scripts/build-deb.sh

rpm:
	VERSION=$(VERSION) ARCH=$${ARCH:-amd64} ./scripts/build-rpm.sh

installer-test: package
	sudo ./scripts/test-install-clickhouse.sh

clean:
	rm -rf dist/*

release-check:
	./scripts/release-check.sh

sbom:
	VERSION=$(VERSION) python3 scripts/generate-sbom.py
