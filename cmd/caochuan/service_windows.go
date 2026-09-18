//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const svcName = "caochuan"

// serviceMain 处理 service 子命令：受 SCM 拉起时直接运行业务，否则执行管理动作。
// 用法:
//
//	caochuan service install -role server|client -c 配置路径
//	caochuan service remove|start|stop
func serviceMain(args []string) {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		slog.Error("判断服务环境失败", "err", err)
		osExit(1)
	}
	if isSvc {
		// SCM 拉起：os.Args = [exe, service, -role, server, -c, ...]
		role, cfgPath := parseServiceArgs(os.Args[2:])
		svc.Run(svcName, &caochuanService{role: role, cfgPath: cfgPath})
		return
	}
	if len(args) == 0 {
		fmt.Println("用法: caochuan service install -role server|client -c 配置路径 | remove | start | stop")
		osExit(2)
	}
	switch args[0] {
	case "install":
		role, cfgPath := parseServiceArgs(args[1:])
		if role != "server" && role != "client" {
			fmt.Println("-role 必须是 server 或 client")
			osExit(2)
		}
		if err := installService(role, cfgPath); err != nil {
			fmt.Println("安装失败:", err)
			osExit(1)
		}
		fmt.Printf("服务 %s 已安装并启动（%s -c %s）\n", svcName, role, cfgPath)
	case "remove":
		if err := removeService(); err != nil {
			fmt.Println("卸载失败:", err)
			osExit(1)
		}
		fmt.Println("服务已卸载")
	case "start":
		mustControlService(func(s *mgr.Service) error { return s.Start() })
		fmt.Println("服务已启动")
	case "stop":
		mustControlService(func(s *mgr.Service) error {
			_, err := s.Control(svc.Stop)
			return err
		})
		fmt.Println("服务已停止")
	default:
		fmt.Println("未知子命令:", args[0])
		osExit(2)
	}
}

func parseServiceArgs(args []string) (role, cfgPath string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "-c":
			if i+1 < len(args) {
				cfgPath = args[i+1]
				i++
			}
		}
	}
	if cfgPath == "" {
		cfgPath = "conf/" + role + ".json"
	}
	return role, cfgPath
}

type caochuanService struct{ role, cfgPath string }

func (s *caochuanService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		if s.role == "client" {
			done <- runClient(ctx, []string{"-c", s.cfgPath}, newRing())
		} else {
			done <- runServer(ctx, []string{"-c", s.cfgPath}, newRing())
		}
	}()
	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done: // 进程自己退出了
			cancel()
			slog.Error("服务进程退出", "err", err)
			return false, 1
		}
	}
}

func connectMgr() (*mgr.Mgr, *mgr.Service) {
	m, err := connectMgrE()
	if err != nil {
		fmt.Println("打开服务管理器失败（需要管理员权限）:", err)
		osExit(1)
	}
	s, err := m.OpenService(svcName)
	if err != nil {
		fmt.Printf("服务 %s 未安装: %v\n", svcName, err)
		osExit(1)
	}
	return m, s
}

func connectMgrE() (*mgr.Mgr, error) { return mgr.Connect() }

func mustControlService(fn func(*mgr.Service) error) {
	m, s := connectMgr()
	defer m.Disconnect()
	defer s.Close()
	if err := fn(s); err != nil {
		fmt.Println("操作失败:", err)
		osExit(1)
	}
}

func installService(role, cfgPath string) error {
	exepath, err := osExecutable()
	if err != nil {
		return err
	}
	m, err := connectMgrE()
	if err != nil {
		return fmt.Errorf("需要管理员权限: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("服务已存在，先执行 caochuan service remove")
	}
	s, err := m.CreateService(svcName, exepath, mgr.Config{
		DisplayName: "Caochuan Forward",
		Description: "草船 TCP/UDP 转发与内网穿透 (" + role + ")",
		StartType:   mgr.StartAutomatic,
	}, "service", "-role", role, "-c", cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	// 崩溃自动重启
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 60)
	return s.Start()
}

func removeService() error {
	m, s := connectMgr()
	defer m.Disconnect()
	defer s.Close()
	st, err := s.Query()
	if err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		for i := 0; i < 30; i++ {
			time.Sleep(time.Second)
			if st, err = s.Query(); err == nil && st.State == svc.Stopped {
				break
			}
		}
	}
	return s.Delete()
}
