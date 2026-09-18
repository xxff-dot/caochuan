//go:build !windows

package main

import "fmt"

// serviceMain 在非 Windows 平台仅提示使用 systemd。
func serviceMain(args []string) {
	fmt.Println("service 子命令仅支持 Windows；Linux 开机自启请使用 systemd，模板见 deploy/caochuan.service")
	osExit(2)
}
