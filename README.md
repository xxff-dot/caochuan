# caochuan（草船）

Go 编写的单二进制 TCP/UDP 端口转发与内网穿透工具，内置 Web 管理面板。

- **正向转发**：服务器端口 → 任意目标地址（不经过客户端）
- **内网穿透**：服务器端口 → 内网客户端侧的服务（client 主动外连，无需公网 IP）
- **反向通道**：客户端本机开端口 → 服务器侧目标（服务器本身或其内网），规则自动下发到 client
- **SOCKS5 出口代理**：client 本机起 SOCKS5 端口，内网设备经服务器网络访问目标（域名由服务器解析）
- TCP 与 UDP 都支持；UDP 在隧道内封帧传输
- **隧道默认 TLS 加密**，client 可锁定服务器证书指纹防中间人
- **规则级控制**：来源 IP 白名单、带宽限速（Mbps）、连接数上限、TCP 空闲超时
- **IP 黑名单**：面板与隧道都拒绝（回环豁免），优先于一切放行规则
- **配置导入/导出**：面板一键备份恢复
- **Prometheus 指标**：`/<随机路径>/metrics`，每规则流量/连接数、客户端在线状态
- Web 面板集中管理规则并实时下发，客户端零规则配置；规则按客户端分组展示
- 实时速率/累计流量/连接数 + 每规则**历史速率图表**（24h）；客户端在线状态；运行日志（可选落盘轮转）
- 面板：随机路径 + IP 白名单（手动 CIDR ∪ 在线客户端来源 IP 自动放行）+ 密码登录（可免密）
- 多客户端接入，每个 token 对应一台内网机；面板可见客户端版本
- 配置持久化为单个 JSON 文件；支持 systemd / Windows 服务开机自启

## 快速开始

### 构建参数（示例，按实际情况调整）

```bash
go build -o caochuan.exe ./cmd/caochuan                 # Windows
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o caochuan ./cmd/caochuan
```

### 服务器端（公网机器）

```bash
./caochuan server                # 首次启动自动生成 server.json 并打印初始密码
```

默认监听：隧道 `:7000`（TLS）、面板 `:7500`。首次启动会打印面板随机路径、初始密码与
**隧道证书指纹**（填到 client 配置里防中间人）。浏览器打开 `http://服务器IP:7500/<随机路径>/`：

1. **客户端** 页添加一台内网机，复制其 token
2. **转发规则** 页新建规则：
   - 正向：方向选「正向」，目标填服务器视角的地址（如 `127.0.0.1:80`）
   - 穿透：方向选目标客户端，目标填**从该内网机访问**的地址（如 `127.0.0.1:5000`）
   - 可选：来源白名单、限速（Mbps）、连接数上限

### 内网机

```bash
./caochuan client                # 首次运行生成 client.json 模板
```

填入 `server_addr`（公网服务器隧道地址）、token，并建议把服务器日志里的证书指纹填到
`tls_fingerprint`，重启即可，规则全部由面板下发。

## 配置说明（server.json）

```jsonc
{
  "tunnel_addr": "0.0.0.0:7000",   // 隧道监听（client 连这里，默认 TLS）
  "panel_addr":  "0.0.0.0:7500",   // Web 面板监听
  "password":    "xxxx",           // 面板登录密码（no_auth=true 时忽略）
  "no_auth":     false,            // 免密模式：跳过登录，仍受白名单与随机路径保护
  "panel_prefix":"xK3mP9qR",       // 面板随机路径前缀；留空启动时自动生成
  "ip_whitelist": [],              // 面板 IP 白名单（IP/CIDR）；留空 = 仅本机 + 在线客户端来源 IP
  "secret":      "...",            // 会话签名密钥（自动生成，勿改）
  "no_tls":      false,            // 关闭隧道 TLS（明文，不推荐）
  "tls_cert":    "",               // 自有证书路径；留空自动生成自签证书
  "tls_key":     "",               // 自有私钥路径
  "log_file":    "",               // 日志文件（10MB×3 份轮转）；留空仅输出控制台
  "clients": [ {"name": "home-nas", "token": "..."} ],
  "rules": [
    {"id": "...", "name": "web", "side": "server", "proto": "tcp", "listen": 8080,
     "client": "",                 // 空=正向；填客户端名=穿透；side="client"=反向
     "target": "10.0.0.2:80",
     "allow_from": [],             // 来源白名单（IP/CIDR）；空=不限制
     "max_mbps": 0,                // 带宽上限 Mbps；0=不限
     "max_conns": 0,               // 连接数上限；0=不限
     "enabled": true}
  ]
}
```

client.json 四项：`server_addr`、`token`、`no_tls`（默认 false）、`tls_fingerprint`（推荐填服务器指纹），
另有可选 `log_file`。

## 开机自启

Linux（systemd）：

```bash
cp deploy/caochuan.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now caochuan
```

Windows（管理员）：

```
caochuan service install -role server -c C:\caochuan\server.json
caochuan service install -role client -c C:\caochuan\client.json
caochuan service remove|start|stop
```

## 安全提示

- 隧道默认 **TLS 加密**（自动生成自签证书），client 配置 `tls_fingerprint`（见服务器启动日志）可防中间人；两端设 `no_tls: true` 可关闭
- 面板密码登录有防爆破锁定（5 次失败锁 10 分钟）；白名单留空时仅本机（回环 + 本机网卡地址）与在线客户端来源 IP 可访问
- 配置文件中的密码、token、secret 与 server.key 为敏感明文，请保证文件权限（Windows 服务默认以 LocalSystem 运行）

## 文档

- [快速上手](docs/01-快速上手.md)
- [部署与配置](docs/02-部署与配置.md)（systemd / Windows 服务 / 配置参考 / 安全三层）
- [面板使用](docs/03-面板使用.md)（三种方向 / 分组 / 统计 / 白名单）
- [架构与协议](docs/04-架构与协议.md)（隧道帧格式 / 控制流 / UDP 封帧 / 统计）
- [测试与发布](docs/05-测试与发布.md)（冒烟测试 / 打包 / CI/CD / 排障速查）

## 目录结构

```
cmd/caochuan/             入口：server/client/service 子命令、Windows SCM 服务
config/                   JSON 配置读写
proto/                    隧道帧协议（鉴权 + smux + UDP 帧）
server/                   公网侧：隧道接入、规则监听、转发、状态、TLS 证书、历史采样
client/                   内网侧：重连、收流、回源、反向监听
panel/                    Web 面板 HTTP API（登录/白名单/CRUD/统计/历史）
logbuf/                   面板日志环形缓冲 + 轮转日志文件
relay/                    双向连接拷贝 + 令牌桶限速
logbuf/                   面板日志环形缓冲
web/                      内嵌前端单页（go:embed，无 npm 构建链）
conf/                     配置目录（server.json/client.json 运行生成；*.example.json 模板）
docs/                     项目文档
scripts/package.sh        打包：交叉编译 + upx 压缩 + conf/ 布局 → dist/
scripts/smoke.sh          本地冒烟测试（正向/穿透/反向 × TCP/UDP + 面板，自动清理）
deploy/                   systemd 单元模板
```

## 打包

```bash
bash scripts/package.sh 0.1.0
```

产出 `dist/caochuan-<版本>-windows-amd64.zip` 与 `caochuan-<版本>-linux-amd64.tar.gz`，
二进制经 upx 压缩（未装 upx 自动跳过），包内含 `conf/` 示例配置与启停脚本。
