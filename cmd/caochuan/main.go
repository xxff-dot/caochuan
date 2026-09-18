// caochuan（草船）— TCP/UDP 转发与内网穿透工具。
//
// 用法:
//
//	caochuan server  -c conf/server.json   公网侧：面板 + 隧道 + 转发
//	caochuan client  -c conf/client.json   内网侧：连接 server 回源
//	caochuan service install -role server|client -c 路径   (仅 Windows) 安装系统服务
//	caochuan service remove|start|stop                     (仅 Windows) 管理服务
//	caochuan version                                       查看版本
package main

import (
	"context"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/xxff-dot/caochuan/logbuf"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ring := logbuf.New(1000)
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(os.Stdout, ring), nil)))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(ctx, os.Args[2:], ring)
	case "client":
		err = runClient(ctx, os.Args[2:], ring)
	case "service":
		serviceMain(os.Args[2:])
		return
	case "version", "-v", "--version":
		fmt.Println("caochuan", version)
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		stdlog.Fatalf("退出: %v", err)
	}
}

func usage() {
	fmt.Print(`caochuan（草船）— TCP/UDP 转发与内网穿透

用法:
  caochuan server  [-c 配置文件]     启动公网服务端（默认 conf/server.json）
  caochuan client  [-c 配置文件]     启动内网客户端（默认 conf/client.json）
  caochuan service install -role server|client -c 配置文件   安装 Windows 服务
  caochuan service remove|start|stop                         管理 Windows 服务
  caochuan version

Linux 开机自启请使用 systemd，模板见 deploy/caochuan.service。
`)
}
