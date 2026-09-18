# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

caochuan（草船）— Go 编写的单二进制 TCP/UDP 端口转发与内网穿透工具，内置 Web 管理面板。
- `server` 角色：公网机器，跑 Web 面板 + 隧道端点 + 转发监听；规则在面板集中管理并经隧道下发
- `client` 角色：内网机器，主动外连 server（token 鉴权），按 server 指示回源到本地服务，本身无状态
- 规则两类统一处理：`client` 字段为空 = 正向转发（server 本机 → target）；非空 = 穿透（server 监听端口 → 该 client 内网的 target）
- TCP 与 UDP 都支持穿透；UDP 封帧走隧道

## 常用命令

```bash
go build ./...                    # 编译
go vet ./...                      # 静态检查（无测试框架，改动后至少过 build+vet）
go build -o caochuan.exe ./cmd/caochuan          # 本地运行二进制
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o caochuan-linux-amd64 ./cmd/caochuan
bash scripts/package.sh 0.1.0     # 打包：交叉编译 + upx + conf/ 布局 → dist/
```

本地冒烟测试（构建 + 起 server/client/目标 + 验证三条链路，自动清理）：
```bash
bash scripts/smoke.sh
```

注意：本机用 `py` 而不是 `python`/`python3`。

## 架构

- `cmd/caochuan/` 入口：server/client/service 子命令；Windows SCM 服务（`service_windows.go`，非 Windows 为 `service_other.go` 桩），服务内同样走 runServer/runClient
- `proto/` 隧道协议：连接先发 `[2B len][JSON AuthRequest]` 鉴权帧，之后升级为 smux 会话。每条数据流首帧 `[2B len][JSON StreamHeader{ID,Target,UDP}]`；UDP=true 时流内为连续帧 `[4B connID][2B len][payload]`，connID 区分不同访客地址。server 永远主动 OpenStream，client 只 Accept
- `server/`：`Run` 监听隧道；`applyRulesLocked` 按配置 diff 启停规则监听（runner/proto 匹配即跳过）。TCP 直接 io.Copy 双向计数；UDP 分 `udpLocalRelay`（NAT 式 socket 映射）与 `udpTunnelRelay`（访客地址↔connID↔隧道帧）两条路。`state.go` 是面板数据层：规则 CRUD（改即存盘+热生效）、客户端管理、白名单
- `client/`：指数退避重连（存活超过 30s 重置退避）；AcceptStream → 读 header → dial target；UDP 流按 connID 维护多个到 target 的 socket，空闲 90s 回收
- `panel/`：stdlib `http.ServeMux`（Go 1.22+ 方法+路径路由）。会话 = HMAC(secret) 签名的过期时间 cookie。访问判定 `IPAllowed` = 回环 ∪ 手动 CIDR 白名单 ∪ 在线 client 来源 IP（自动放行）。登录防爆破：5 次失败锁 IP 10 分钟
- 统计：server 侧每规则 `Stat`（atomic 字节/连接计数），面板前端 2s 轮询、用差值算速率，无历史存储（SQLite 类需求未做）
- `web/`：`web.go` 用 go:embed 挂 `files/index.html` 单页（手写 CSS/JS，无外部依赖、无构建链）
- 配置：`config/` JSON，默认路径 `conf/server.json`、`conf/client.json`；首次启动自动生成并打印随机密码；保存为 tmp+rename 原子写

## 部署与测试环境

- 详细文档在 `docs/`（快速上手/部署配置/面板使用/架构协议/测试发布），改功能时同步更新对应文档
- 测试服务器：`root@47.237.125.11`（SSH 免密），安全组仅放行 34600-35600/TCP（UDP 未放行）
- 服务器当前部署：`/opt/caochuan/`，systemd 单元名 `caochuan`，隧道 34600、面板 34601，
  面板免密（no_auth=true）+ 随机路径（见其 server.json 的 panel_prefix）
- 本机跑着 client（`caochuan.exe client -c conf/client.json`，日志 `caochuan-client.log`）
- 更新部署：交叉编译 → scp 到 /tmp → stop → install -m755 → start；日志 `journalctl -u caochuan`

## 约定

- 所有文件 LF 换行（`.gitattributes` 已强制）
- 外部依赖只有 `github.com/xtaci/smux` 与 `golang.org/x/sys`，新增依赖需谨慎
- `conf/server.json`、`conf/client.json` 是运行时生成的真实配置，已 gitignore；`conf/*.example.json` 模板受版本控制
- 禁止用 sed/awk/PowerShell 做文本替换，一律用 Edit 工具
