# Kubectl debug

![license](https://img.shields.io/hexpm/l/plug.svg)
[![travis](https://travis-ci.org/cnzf1/kubectl-debug.svg?branch=master)](https://travis-ci.org/cnzf1/kubectl-debug)
[![Go Report Card](https://goreportcard.com/badge/github.com/cnzf1/kubectl-debug)](https://goreportcard.com/report/github.com/cnzf1/kubectl-debug)
[![docker](https://img.shields.io/docker/pulls/cnzf1/debugger.svg)](https://hub.docker.com/r/cnzf1/debugger)

[English](/README.md)

# Overview

`kubectl-debug` 是一个简单的 kubectl 插件, 能够帮助你便捷地进行 Kubernetes 上的 Pod 排障诊断. 背后做的事情很简单: 在运行中的 Pod 上额外起一个新容器, 并将新容器加入到目标容器的 `pid`, `network`, `user` 以及 `ipc` namespace 中, 这时我们就可以在新容器中直接用 `netstat`, `tcpdump` 这些熟悉的工具来解决问题了, 而旧容器可以保持最小化, 不需要预装任何额外的排障工具.

更详细的介绍信息，可以参考这篇[博客文章](https://aleiwu.com/post/kubectl-debug-intro/)

- [截图](#截图)
- [快速开始](#快速开始)
- [构建项目](#构建项目)
- [port-forward 和 debuggerless 模式](#port-forward-模式和-debuggerless-模式)
- [配置](#配置)
- [权限](#权限)
- [路线图](#路线图)
- [贡献代码](#贡献代码)

# 截图

![gif](/docs/kube-debug.gif)

# 快速开始

## 安装 kubectl debug 插件

安装 kubectl 插件:

使用 Homebrew:
```shell
brew install cnzf1/tap/kubectl-debug
```

直接下载预编译的压缩包:
```bash
export PLUGIN_VERSION=0.1.1
# linux x86_64
curl -Lo kubectl-debug.tar.gz https://github.com/cnzf1/kubectl-debug/releases/download/v${PLUGIN_VERSION}/kubectl-debug_${PLUGIN_VERSION}_linux_amd64.tar.gz
# macos
curl -Lo kubectl-debug.tar.gz https://github.com/cnzf1/kubectl-debug/releases/download/v${PLUGIN_VERSION}/kubectl-debug_${PLUGIN_VERSION}_darwin_amd64.tar.gz

tar -zxvf kubectl-debug.tar.gz kubectl-debug
sudo mv kubectl-debug /usr/local/bin/
```

Windows 用户可以从 [release page](https://github.com/cnzf1/kubectl-debug/releases/tag/v0.1.1) 进行下载并添加到 PATH 中

## (可选) 安装 debugger DaemonSet   

`kubectl-debug` 包含两部分, 一部分是用户侧的 kubectl 插件, 另一部分是部署在所有 k8s 节点上的 debugger(用于启动"新容器", 同时也作为 SPDY 连接的中继). 在 `debuggerless` 中, `kubectl-debug` 会在 debug 开始时创建 debugger Pod, 并在结束后自动清理.(默认开启serverless模式)

`debuggerless` 虽然方便, 但会让 debug 的启动速度显著下降, 你可以通过预先安装 debugger 的 DaemonSet 并配合 --debuggerless=false 参数来使用 debugger 模式, 加快启动速度:

```bash
# 如果你的kubernetes版本为v1.16或更高
kubectl apply -f https://raw.githubusercontent.com/cnzf1/kubectl-debug/master/scripts/debugger_daemonset.yml
# 如果你使用的是旧版本的kubernetes(<v1.16), 你需要先将apiVersion修改为extensions/v1beta1, 可以如下操作
wget https://raw.githubusercontent.com/cnzf1/kubectl-debug/master/scripts/debugger_daemonset.yml
sed -i '' '1s/apps\/v1/extensions\/v1beta1/g' debugger_daemonset.yml
kubectl apply -f debugger_daemonset.yml
# 或者使用helm安装
helm install kubectl-debug -n=debugger ./contrib/helm/kubectl-debug
# 使用daemonset debugger模式(关闭serverless模式)
kubectl debug --debuggerless=false POD_NAME
```

简单使用:
```bash
# kubectl 1.12.0 或更高的版本, 可以直接使用:
kubectl debug -h
# 假如安装了 debugger 的 daemonset, 可以使用 --debuggerless=false 来加快启动速度
# 之后的命令里会使用默认的serverless模式
kubectl debug POD_NAME

# 假如 Pod 处于 CrashLookBackoff 状态无法连接, 可以复制一个完全相同的 Pod 来进行诊断
kubectl debug POD_NAME --fork

# 当使用fork mode时,如果需要复制出来的pod保留原pod的labels,可以使用 --fork-pod-retain-labels 参数进行设置(注意逗号分隔,且不允许空格)
# 示例如下
# 若不设置,该参数默认为空(既不保留原pod的任何labels,fork出来的新pod的labels为空)
kubectl debug POD_NAME --fork --fork-pod-retain-labels=<labelKeyA>,<labelKeyB>,<labelKeyC>

# 为了使 没有公网 IP 或无法直接访问(防火墙等原因)的 NODE 能够访问, 默认开启 port-forward 模式
# 如果不需要开启port-forward模式, 可以使用 --port-forward=false 来关闭
kubectl debug POD_NAME --port-forward=false --debuggerless=false --daemonset-ns=kube-system --daemonset-name=debugger

# 老版本的 kubectl 无法自动发现插件, 需要直接调用 binary
kubectl-debug POD_NAME

# 使用私有仓库镜像,并设置私有仓库使用的kubernetes secret
# secret data原文请设置为 {Username: <username>, Password: <password>}
# 默认secret_name为kubectl-debug-registry-secret,默认namspace为default
kubectl-debug POD_NAME --image calmkart/netshoot:latest --registry-secret-name <k8s_secret_name> --registry-secret-namespace <namespace>

# 在默认的serverless模式中,你可以设置debugger pod的resource资源限制,如下示例
# 若不设置,默认为空
kubectl-debug POD_NAME --debugger-pod-cpu-requests=250m --debugger-pod-cpu-limits=500m --debugger-pod-memory-requests=200Mi --debugger-pod-memory-limits=500Mi
```

举例:
```bash
# 怎样创建一个私有仓库镜像secret
# 以用户名'calmkart' 密码'calmkart'为例
# 更多创建方式请参考kubernetes官方文档
# https://kubernetes.io/docs/concepts/configuration/secret/
echo -n '{Username: calmkart, Password: calmkart}' > ./registrySecret.txt
kubectl create secret generic kubectl-debug-registry-secret --from-file=./registrySecret.txt
```

# 构建项目

克隆仓库, 然后执行:
```bash
# make will build plugin binary and debugger image
make
# install plugin
mv kubectl-debug /usr/local/bin

# build plugin only
make plugin
# build debugger only
make debugger-docker
```

# port-forward 模式和 debuggerless 模式(默认开启)

- `port-foward`模式：默认情况下，`kubectl-debug`会直接与目标宿主机建立连接。当`kubectl-debug`无法与目标宿主机直连时，可以开启`port-forward`模式。`port-forward`模式下，本机会监听localhost:debuggerPort，并将数据转发至目标Pod的debuggerPort端口。

- `debuggerless`模式： 默认情况下，`debugger`需要预先部署在集群每个节点上，会一直消耗集群资源，然而调试 Pod 是低频操作。为避免集群资源损失，在[#31](https://github.com/cnzf1/kubectl-debug/pull/31)增加了`debuggerless`模式。`debuggerless`模式下，`kubectl-debug`会先在目标Pod所在宿主机上启动`debugger`，然后再启动调试容器。用户调试结束后，`kubectl-debug`会依次删除调试容器和在目的主机启动的`debugger`。


# 配置

`kubectl-debug` 使用 [nicolaka/netshoot](https://github.com/nicolaka/netshoot) 作为默认镜像. 默认镜像和指令都可以通过命令行参数进行覆盖. 考虑到每次都指定有点麻烦, 也可以通过文件配置的形式进行覆盖, 编辑 `~/.kube/debug-config` 文件:

```yaml
# debugger 映射到宿主机的端口
# 默认 10027
debuggerPort: 10027

# 是否开启ageless模式
# 默认 true
debuggerless: true
# debuggerPod 的 namespace, serverless模式可用
# 默认 default
debuggerPodNamespace: default
# debuggerPod 的名称前缀，后缀是目的主机名, serverless模式可用
# 默认 debugger-pod
debuggerPodNamePrefix: debugger-pod
# debuggerPod 的镜像, serverless模式可用
# 默认 cnzf1/debugger:latest
debuggerImage: cnzf1/debugger:latest

# debugger DaemonSet 的名字, port-forward 模式时会用到
# 默认 'debugger'
debuggerDaemonset: debugger
# debugger DaemonSet 的 namespace, port-forward 模式会用到
# 默认 'default'
debuggerNamespace: kube-system
# 是否开启 port-forward 模式
# 默认 true
portForward: true
# image of the debug container
# default as showed
image: nicolaka/netshoot:latest
# start command of the debug container
# default ['bash']
command:
- '/bin/bash'
- '-l'
# private docker registry auth kuberntes secret, default is kubectl-debug-registry-secret
# 使用私有仓库镜像,并设置私有仓库使用的kubernetes secret
# secret data原文请设置为 {Username: <username>, Password: <password>}
# 默认RegistrySecretName为kubectl-debug-registry-secret,默认RegistrySecretNamespace为default
RegistrySecretName: my-debug-secret
RegistrySecretNamespace: debug
# 在默认的serverless模式下可以设置debugger pod的resource资源限制
# 若不设置,默认为空
debuggerCpuRequests: ""
debuggerCpuLimits: ""
debuggerMemoryRequests: ""
debuggerMemoryLimits: ""
# 当使用fork mode时,如果需要复制出来的pod保留原pod的labels,可以设置需要保留的labels列表
# 格式为[]string
# 默认为空(既不保留任何原POD的labels,新fork出pod的labels)
forkPodRetainLabels: []
```

> `kubectl-debug` 会将容器的 entrypoint 直接覆盖掉, 这是为了避免在 debug 时不小心启动非 shell 进程.

# 权限

目前, `kubectl-debug` 复用了 `pod/exec` 资源的权限来做鉴权. 也就是说, `kubectl-debug` 的权限要求是和 `kubectl exec` 一致的.

# 路线图

- [ ] 安全: 目前, `kubectl-debug` 是在客户端做鉴权的, 这部分应当被移动到服务端(debugger) 中
- [ ] 更多的单元测试
- [ ] 更多的故障诊断实例
- [ ] e2e 测试

# 贡献代码

欢迎贡献代码或 issue!
