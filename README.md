# eBPF-demo

使用 C 语言基于 libbpf 开发 eBPF 程序

## 准备环境

Ubuntu 24.04 安装如下依赖，有些依赖包不是立即就需要的，是在开发稍微复杂的程序时才会用到，而且可能还需要准备其他依赖包。
sudo apt install build-essential clang gcc llvm libbpf-dev libelf-dev libpcap-dev linux-bpf-dev linux-headers-$(uname -r) linux-tools-$(uname -r) make zlib1g-dev libbpf-tools

## 示例

具体内容参考代码

## 资料

### BCC

BCC - Tools for BPF-based Linux IO analysis, networking, monitoring, and more
https://github.com/iovisor/bcc
https://github.com/iovisor/bcc/blob/master/INSTALL.md

基于 BCC 的工具代码
https://github.com/iovisor/bcc/tree/master/tools
基于 libbpf 的工具代码
https://github.com/iovisor/bcc/tree/master/libbpf-tools

### libbpf

This is the official home of the libbpf library.
https://github.com/libbpf/libbpf

Scaffolding for BPF application development with libbpf and BPF CO-RE
https://github.com/libbpf/libbpf-bootstrap
https://github.com/libbpf/libbpf-bootstrap/blob/master/examples

This is the official home for bpftool.
https://github.com/libbpf/bpftool

