.PHONY: prepare build plugin agent docker check

NS_NAME=tools
AGENT_IMG=cnzf1/debugger:latest
NET_IMG=cnzf1/debugger-tool:latest

PKG_NAME=github.com/cnzf1/kubectl-debug
AGENT_FLAG = -X '$(PKG_NAME)/pkg/plugin.defaultAgentImage=$(AGENT_IMG)'
NET_FLAG=-X '$(PKG_NAME)/pkg/plugin.defaultImage=$(NET_IMG)'
NS_FLAG=-X '$(PKG_NAME)/pkg/plugin.defaultNS=$(NS_NAME)'


VER_FLAG = $(shell ./version.sh)
GOENV  := GO15VENDOREXPERIMENT="1" GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=arm64
GO := $(GOENV) go

all: build docker

build: plugin agent

plugin:
	$(GO) build -ldflags "$(VER_FLAG) $(AGENT_FLAG) $(NET_FLAG) $(NS_FLAG)" -o kubectl-debug cmd/plugin/main.go
	@sudo cp kubectl-debug /usr/local/bin

agent:
	$(GO)  build -ldflags "-linkmode 'external' -extldflags '-static' $(VER_FLAG)" -o debug-agent cmd/agent/main.go

prepare:
	@sudo docker pull nicolaka/netshoot:latest
	@sudo docker tag nicolaka/netshoot:latest $(NET_IMG)

docker:
	@sudo docker build . --no-cache -t $(AGENT_IMG)
	@sudo docker push $(AGENT_IMG)
	@sed -i "s#image:.*#image: $(AGENT_IMG)#g" scripts/agent_daemonset.yml
	@sed -i "s#namespace:.*#namespace: $(NS_NAME)#g" scripts/agent_daemonset.yml

check:
	find . -iname '*.go' -type f | grep -v /vendor/ | xargs gofmt -l
	GO111MODULE=on go test -v -race ./...
	$(GO) vet ./...
