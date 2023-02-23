.PHONY: build plugin agent docker check

AGENT_IMG = "cnzf1/debug-agent:latest"

VERSION = $(shell ./version.sh)
GOENV  := GO15VENDOREXPERIMENT="1" GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=arm64
GO := $(GOENV) go

default: build docker

build: plugin agent

plugin:
	$(GO) build -ldflags "$(VERSION) -X 'github.com/cnzf1/kubectl-debug/pkg/plugin.defaultAgentImage=$(AGENT_IMG)'" -o kubectl-debug cmd/plugin/main.go

docker:
	@sudo docker build . --no-cache -t $(AGENT_IMG)
	@sudo docker push $(AGENT_IMG)
	@sed -i "s#image:.*#image: $(AGENT_IMG)#g" scripts/agent_daemonset.yml

agent:
	$(GO)  build -ldflags "-linkmode 'external' -extldflags '-static' $(VERSION)" -o debug-agent cmd/agent/main.go

check:
	find . -iname '*.go' -type f | grep -v /vendor/ | xargs gofmt -l
	GO111MODULE=on go test -v -race ./...
	$(GO) vet ./...
