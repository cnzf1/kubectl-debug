.PHONY: prepare build plugin debugger docker check

NS_NAME=tools
DEBUGGER_IMG=cnzf1/debugger:latest
NET_IMG=cnzf1/debugger-tool:latest

PKG_NAME=github.com/cnzf1/kubectl-debug
DEBUGGER_FLAG = -X '$(PKG_NAME)/pkg/plugin.defaultDebuggerImage=$(DEBUGGER_IMG)'
NET_FLAG=-X '$(PKG_NAME)/pkg/plugin.defaultImage=$(NET_IMG)'
NS_FLAG=-X '$(PKG_NAME)/pkg/plugin.defaultNS=$(NS_NAME)'


VER_FLAG = $(shell ./version.sh)
GOENV  := GO15VENDOREXPERIMENT="1" GO111MODULE=on CGO_ENABLED=0
GO := $(GOENV) go

all: build docker

build: plugin debugger

plugin:
	$(GO) build -ldflags "$(VER_FLAG) $(DEBUGGER_FLAG) $(NET_FLAG) $(NS_FLAG)" -o kubectl-debug cmd/plugin/main.go
	@strip kubectl-debug
	@sudo cp kubectl-debug /usr/local/bin

debugger:
	$(GO) build -ldflags "-linkmode 'external' -extldflags '-static' $(VER_FLAG)" -o debugger cmd/debugger/main.go
	@strip debugger

prepare:
	@sudo docker pull nicolaka/netshoot:latest
	@sudo docker tag nicolaka/netshoot:latest $(NET_IMG)
	@sudo docker push $(NET_IMG)

docker:
	@sudo docker build . --no-cache -t $(DEBUGGER_IMG)
	@sudo docker push $(DEBUGGER_IMG)
	@sed -i "s#image:.*#image: $(DEBUGGER_IMG)#g" scripts/debugger_daemonset.yml
	@sed -i "s#namespace:.*#namespace: $(NS_NAME)#g" scripts/debugger_daemonset.yml

check:
	find . -iname '*.go' -type f | grep -v /vendor/ | xargs gofmt -l
	GO111MODULE=on go test -v -race ./...
	$(GO) vet ./...
