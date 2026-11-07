# NodeLite

NodeLite 是一个运行在 Linux 终端下的代理节点部署与订阅管理工具。安装后在 SSH 终端输入 `nl`（或 `NL`）即可通过交互式菜单完成节点创建、单节点链接复制、配置文件导出、在线订阅开启、端口修改、核心升级、历史配置回滚及连通性排查。

本项目针对小内存 VPS（128 MB 及以上）与共享 IP 的 NAT 服务器进行了轻量化设计：管理界面仅在执行命令时运行，退出后不驻留后台；代理服务由单个 `sing-box` 进程承载，在线订阅由基于 Python 3 标准库的轻量 HTTP/HTTPS 服务提供，无需安装 Docker、Node.js、数据库或 Web 面板。

---

## 主要功能

- **多协议支持与真实出站校验**：支持 VLESS Reality、VMess、Hysteria2、TUIC、Trojan、Shadowsocks 2022 六种协议。创建节点或修改配置时，先执行 `sing-box check` 语法检查，再通过本机临时客户端发起真实协议握手并访问 HTTPS 204 测试页，验证通过后才正式生效；若任一步骤失败则自动回滚至上一版配置。
- **低内存占用**：管理程序仅使用 Python 3 标准库，无第三方依赖。`sing-box` 默认设置内存软上限（`GOMEMLIMIT=32MiB`），在线订阅服务采用小栈线程与只读快照设计，无节点时自动停止。
- **多客户端自适应订阅**：开启在线订阅后，服务端可根据客户端请求的 `User-Agent` 自动返回对应格式的配置，同一条订阅地址可直接在主流代理软件中使用；节点增删、改名或换端口后订阅内容自动同步。
- **内置国内直连与防污染分流规则**：生成的 Clash / Mihomo 配置文件内置 Fake-IP DNS、国内 DoH/DoT 解析以及常见国内网站、大陆 IP（`GEOIP,CN,DIRECT`）直连规则，国内访问直接连接，境外流量按策略转发。
- **Reality 握手域名测速优选**：创建 VLESS Reality 节点时，自动并发测试当前服务器到各候选 TLS 1.3 域名的握手延迟，默认选用延迟最低的域名。
- **多机节点汇总与链式代理**：支持将其他 VPS 的单节点分享链接汇总到当前订阅中，并支持配置基于 `dialer-proxy` 的前置中转与落地链式代理。
- **在线更新**：支持通过 `nl update` 或菜单选项从 GitHub 拉取最新安装包并校验 SHA-256，更新管理脚本时不中断正在运行的节点服务。

---

## 客户端兼容说明

NodeLite 提供单节点分享链接、本地导出文件以及在线自动更新订阅三种导入方式。在线订阅服务会根据客户端请求头自动匹配返回格式，也支持通过不同后缀路径或 `?flag=` 参数指定格式：

| 客户端类别 | 适配软件 | 订阅返回内容 |
| :--- | :--- | :--- |
| **Clash / Mihomo 系列** | FlClash、Clash Verge Rev、Clash Party、Mihomo Party、Clash for Windows、Stash、Karing、Surfboard、OpenClash | 标准 Clash YAML 配置（含节点组、自动测速、故障转移、DNS 及国内直连分流规则） |
| **通用节点订阅客户端** | v2rayN、v2rayNG、Shadowrocket、NekoBox、Quantumult X、Loon、Streisand、V2Box、Hiddify、PassWall | 标准 Base64 编码节点列表（支持 VLESS、VMess、Hysteria2、TUIC、Trojan、SS2022） |
| **Sing-box 官方客户端** | Sing-box（SFA / SFI / SFM / Windows） | 标准 Sing-box 客户端 JSON 配置（含入站、出站及基础分流规则） |

启用在线订阅后，菜单会同时列出适配不同软件的订阅地址；若在 v2rayN、Shadowrocket 等软件中直接填入 `.yaml` 结尾的订阅链接，服务端也会根据客户端标识自动返回 Base64 节点列表。

---

## 安装与启动

支持 Debian、Ubuntu、Alpine、Rocky、AlmaLinux、CentOS 等主流 Linux 发行版（需具备 `systemd` 或 `OpenRC`），支持 `amd64`、`arm64`、`armv7`、`386` 架构，需以 `root` 权限运行。

### 方式一：命令行在线安装

```sh
curl -fsSL https://raw.githubusercontent.com/qingyechan/NodeLite/main/dist/nodelite.run -o /root/nodelite.run && sh /root/nodelite.run
```

### 方式二：离线安装包安装

下载本仓库的 `dist/nodelite.run` 并上传至服务器 `/root/` 目录，随后执行：

```sh
sh /root/nodelite.run
```

安装完成后，在终端输入 `nl` 或 `NL` 即可打开管理菜单。

---

## 端口填写说明（独立 IP 与 NAT 服务器）

### 1. 独立 IP 服务器（普通 VPS）

拥有独立公网 IP 的服务器无需配置端口映射，节点的公网端口与内部监听端口相同。创建节点时程序会自动推荐未被占用的空闲端口，也可手动指定 `443` 或 `1024–65535` 范围内的端口。

### 2. 共享 IP 服务器（NAT VPS）

NAT 服务器通过服务商后台的“端口映射 / 端口转发”规则将公网端口转发至内部端口。配置前请先核对服务商后台映射表中的**协议类型（TCP / UDP）**、**外部（公网）端口**与**内部（内网）端口**：

| 端口用途 | 要求协议类型 | 服务商后台外部端口（示例） | 服务商后台内部端口（示例） | 填写说明 |
| :--- | :--- | :--- | :--- | :--- |
| **SSH 远程登录** | TCP | `23932` | `22` | 仅用于 SSH 登录服务器，切勿填入节点或订阅配置（程序会自动检测并拦截） |
| **代理节点（TCP 类）** | TCP | `53440` | `10086` | 适用于 VLESS Reality、VMess、Trojan、Shadowsocks 2022；节点公网端口填 `53440`，内部端口填 `10086` |
| **在线订阅服务** | TCP | `40187` | `20000` | 需单独占用一条不同于节点和 SSH 的 TCP 映射；订阅公网端口填 `40187`，内部端口填 `20000` |
| **代理节点（UDP 类）** | UDP | `20381` | `28443` | 仅在服务商后台明确提供 UDP 映射时使用，适用于 Hysteria2、TUIC |

**配置注意事项：**

1. **协议与映射类型对应**：VLESS Reality、VMess、Trojan、Shadowsocks 2022 使用 TCP 传输；Hysteria2、TUIC 使用 UDP 传输。部分 NAT 服务器默认仅提供 TCP 转发，若后台未标明支持 UDP 映射，请优先选择 `VLESS Reality` 等基于 TCP 的协议。
2. **公网端口与内部端口成对填写**：同一条转发规则中的外部端口与内部端口需一一对应填写，不可将不同规则行的端口混用。
3. **节点与订阅端口分离**：代理节点与在线订阅属于两个独立服务，需分别使用不同的端口映射规则。
4. **受限网络下的订阅访问**：若部分服务器机房限制普通端口的 HTTP 访问，可在菜单 `4` 中启用 Cloudflare 隧道（支持固定域名隧道或免域名临时隧道），通过 HTTPS 域名拉取订阅。

---

## 常用命令

除输入 `nl` 进入交互菜单外，也可直接通过命令行参数执行对应操作：

```sh
nl              # 打开中文数字交互菜单（输入 NL 同样有效）
nl links        # 查看所有节点分享链接、外部汇总节点、链式代理与在线订阅地址
nl export       # 在 /etc/nodelite/exports/ 导出 flclash.yaml、links.txt 与 subscription.txt
nl external     # 查看或管理汇总的外部节点与 dialer-proxy 链式代理
nl update       # 从 GitHub 拉取最新版本并校验 SHA-256 在线更新（不中断节点运行）
nl test         # 对所有已配置节点执行本机真实协议连通性自测
nl doctor       # 查看各组件内存占用、证书剩余有效期、端口监听状态与排障说明
nl rollback     # 恢复至上一版保存的节点配置
```

---

## 目录结构

```text
NodeLite/
├── .github/workflows/ci.yml     # GitHub Actions 自动化测试与 Release 构建流程
├── dist/
│   ├── nodelite.run             # 自包含 Linux 安装包（由 terminal/build.py 生成）
│   └── nodelite.run.sha256      # 安装包 SHA-256 校验文件
└── terminal/
    ├── nodelite.py              # 终端交互菜单与命令行入口
    ├── protocols.py             # 六协议配置生成、URI 解析、分流规则与多格式订阅构建
    ├── runtime.py               # 事务提交与回滚、协议自测、订阅服务、核心升级与系统诊断
    ├── install.sh               # Linux 环境检测与安装脚本模板
    ├── build.py                 # 确定性打包脚本
    ├── README.md                # 终端工具补充说明与设计取舍
    └── tests/
        ├── test_terminal.py     # 单元与事务集成测试套件
        └── live_protocols.py    # Linux 本地回环六协议隔离实测脚本
```

---

## 构建与测试

在项目根目录下执行以下命令可重新构建安装包并运行测试套件：

```sh
python -B terminal/build.py
python -B -m unittest discover -s terminal/tests -v
```

更多关于服务目录、旧版本迁移与架构设计的说明，请参阅 [terminal/README.md](terminal/README.md)。
