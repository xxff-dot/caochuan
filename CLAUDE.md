# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

caochuan（草船）— Go 编写的单二进制 TCP/UDP 端口转发与内网穿透工具，内置 Web 管理面板。
- `server` 角色：公网机器，跑 Web 面板 + 隧道端点 + 转发监听；规则在面板集中管理并经隧道下发
- `client` 角色：内网机器，主动外连 server（token 鉴权），按 server 指示回源到本地服务，本身无状态
- 规则三类统一处理：`side=server`（默认）+ `client` 为空 = 正向转发（server 监听端口 → target）；`side=server` + `client` 非空 = 穿透（server 监听端口 → 该 client 内网的 target）；`side=client` = 反向（client 本机监听端口 → 服务器侧 target）
- TCP 与 UDP 都支持；UDP 封帧走隧道；隧道默认 TLS（自签证书自动生成，client 可锁定指纹）
- 规则可配 `allow_from` 来源白名单、`max_mbps` 限速、`max_conns` 连接数上限

## 常用命令

```bash
go build ./...                    # 编译
go vet ./...                      # 静态检查（改动后至少过 build+vet）
go test ./relay/                  # relay 包有限速器单测
go build -o caochuan.exe ./cmd/caochuan          # 本地运行二进制
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o caochuan-linux-amd64 ./cmd/caochuan
bash scripts/package.sh 0.1.0     # 打包：交叉编译 + upx + conf/ 布局 → dist/
```

本地冒烟测试（构建 + 起 server/client/目标 + 验证 8 项含正/穿/反 × TCP/UDP，自动清理）：
```bash
bash scripts/smoke.sh
```

注意：本机用 `py` 而不是 `python`/`python3`。

## 架构

- `cmd/caochuan/` 入口：server/client/service 子命令；Windows SCM 服务（`service_windows.go`，非 Windows 为 `service_other.go` 桩），服务内同样走 runServer/runClient；日志按配置 `log_file` 落盘（10MB×3 轮转）
- `proto/` 隧道协议：TCP 连接默认套 TLS（`server/tls.go` 自签证书自动生成，指纹=SHA-256(证书DER)），先发 `[2B len][JSON AuthRequest{token,host}]` 鉴权帧，之后升级为 smux 会话。每条流首帧 `[2B len][JSON StreamHeader{ID,Target,UDP}]`；UDP 流内为 `[4B connID][2B len][payload]` 帧。控制流（`ID="__control__"`）由 server 打开，下发 `RulePush`/接收 `ReverseStatus`；穿透数据流由 server 打开，**反向数据流由 client 打开**——两侧都有 Open 与 Accept
- `server/`：`Run` 监听隧道；`applyRulesLocked` 按签名（proto+listen+target+client）diff 启停 server 侧监听，传给 goroutine 的是规则**值拷贝**（防配置更新竞态）；Side=client 的规则不在此监听，经控制流下发。TCP 走 `relay.Pipe` 双向计数；UDP 分 `udpLocalRelay`（NAT 式 socket 映射，目标域名 60s 重解析）与 `udpTunnelRelay`（访客↔connID↔隧道帧，访客表 90s 懒过期）。`state.go` 面板数据层：规则 CRUD（存盘+热生效+广播下发）、客户端管理、白名单；`tls.go` 证书；`history.go` 30s 采样 24h 环形
- `client/`：指数退避重连（存活超 30s 重置退避）；AcceptStream → 控制流交给 `reverseMgr`（`reverse.go`：diff 管理反向监听器、回传状态），数据流读 header → dial target；UDP 流按 connID 维护多个到 target 的 socket，空闲 90s 回收
- `panel/`：stdlib `http.ServeMux`（Go 1.22+ 方法+路径路由），挂在 `/<panel_prefix>/` 下。会话 = HMAC(secret) 签名的过期时间 cookie（`no_auth=true` 跳过）。访问判定 `IPAllowed` = 回环 ∪ 本机网卡地址 ∪ 手动 CIDR ∪ 在线 client 来源 IP。登录防爆破：5 次失败锁 IP 10 分钟
- `relay/`：`Pipe` 双向拷贝（双向计数 + 共享令牌桶限速 `Limiter`，`limiter_test.go` 有单测）
- 统计：server 侧每规则 `Stat`（atomic 计数），面板 2s 轮询差值算速率；`/api/history/{id}` 出 24h 采样
- `web/`：`web.go` 用 go:embed 挂 `files/index.html` 单页（手写 CSS/JS canvas 图表，无外部依赖、无构建链）
- 配置：`config/` JSON，默认路径 `conf/server.json`、`conf/client.json`；首次启动自动生成并打印随机密码；保存为 tmp+rename 原子写；空 secret/空密码自动兜底生成

## 部署与测试环境

- 详细文档在 `docs/`（快速上手/部署配置/面板使用/架构协议/测试发布），改功能时同步更新对应文档
- 测试服务器：`root@47.237.125.11`（SSH 免密），安全组仅放行 34600-35600/TCP（UDP 未放行）
- 服务器部署（验收后可能已清）：`/opt/caochuan/`，systemd 单元名 `caochuan`，隧道 34600、面板 34601；验收环境配置见 `docs/05-测试与发布.md`
- 更新部署：交叉编译 → scp 到 /tmp → stop → install -m755 → start；日志 `journalctl -u caochuan`
- 发版：push 到 `main` 触发 CI；打 `v*` tag 触发 Release workflow 自动发版

## 约定

- 所有文件 LF 换行（`.gitattributes` 已强制）
- 外部依赖只有 `github.com/xtaci/smux` 与 `golang.org/x/sys`，新增依赖需谨慎
- `conf/server.json`、`conf/client.json`、`conf/server.crt/key` 是运行时生成的真实文件，已 gitignore；`conf/*.example.json` 模板受版本控制
- 禁止用 sed/awk/PowerShell 做文本替换，一律用 Edit 工具
