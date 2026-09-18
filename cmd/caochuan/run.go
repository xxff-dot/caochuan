package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/xxff-dot/caochuan/client"
	"github.com/xxff-dot/caochuan/config"
	"github.com/xxff-dot/caochuan/logbuf"
	"github.com/xxff-dot/caochuan/panel"
	"github.com/xxff-dot/caochuan/server"
	"github.com/xxff-dot/caochuan/web"
)

// setupLogger 按配置初始化默认日志：stdout + 面板环形缓冲（+ 可选轮转日志文件）。
// 必须在配置加载后调用；Windows 服务模式下 stdout 无处输出，文件是唯一可见日志。
func setupLogger(ring *logbuf.Ring, logFile string) {
	writers := []io.Writer{os.Stdout, ring}
	if logFile != "" {
		writers = append(writers, logbuf.NewRotator(logFile, 10, 3))
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(writers...), nil)))
}

func runServer(ctx context.Context, args []string, ring *logbuf.Ring) error {
	fs_ := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs_.String("c", "conf/server.json", "配置文件路径")
	_ = fs_.Parse(args)

	cfg, generated, err := config.LoadServer(*cfgPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}
	if generated {
		fmt.Printf("=============================================================\n")
		fmt.Printf(" 已生成初始配置 %s\n", *cfgPath)
		fmt.Printf(" 面板初始密码: %s   （请登录后立即修改）\n", cfg.Password)
		fmt.Printf(" 客户端 token: %s（client1）\n", cfg.Clients[0].Token)
		fmt.Printf("=============================================================\n")
	}
	if cfg.PanelPrefix == "" { // 旧配置补随机路径
		cfg.PanelPrefix = config.RandToken()[:8]
		if err := cfg.Save(*cfgPath); err != nil {
			return err
		}
	}
	setupLogger(ring, cfg.LogFile)

	srv, err := server.New(cfg, *cfgPath, ring)
	if err != nil {
		return err
	}

	pnl := panel.New(srv, cfg.Secret, cfg.PanelPrefix, web.UI)
	pnl.NoAuth = cfg.NoAuth
	hs := &http.Server{Addr: cfg.PanelAddr, Handler: pnl.Handler()}
	go func() {
		slog.Info("面板已启动", "addr", cfg.PanelAddr, "path", "/"+cfg.PanelPrefix+"/")
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("面板启动失败", "err", err)
			os.Exit(1) // 面板起不来等于白跑，直接退出让 systemd/服务管理器接管
		}
	}()

	err = srv.Run(ctx)
	_ = hs.Close()
	return err
}

func runClient(ctx context.Context, args []string, ring *logbuf.Ring) error {
	fs_ := flag.NewFlagSet("client", flag.ExitOnError)
	cfgPath := fs_.String("c", "conf/client.json", "配置文件路径")
	_ = fs_.Parse(args)

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("已生成配置模板 %s，请填入 server_addr 和 token 后重新启动\n", *cfgPath)
			return nil
		}
		return fmt.Errorf("读取配置失败: %w", err)
	}
	c := &client.Client{Cfg: cfg, Log: ring, Version: version}
	setupLogger(ring, cfg.LogFile)
	slog.Info("客户端启动", "server", cfg.ServerAddr)
	return c.Run(ctx)
}
