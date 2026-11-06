# NodeLite（轻节点）：VPS 终端节点与轻量订阅管理

在 Linux VPS 的 SSH 终端输入 `nl`（或 `NL`），用中文数字菜单创建节点、复制分享链接、导出 FlClash 配置、开启公网自动更新订阅 URL、修改节点端口（含 443）、改名、删除、升级核心、清理旧版服务、自测或排查连接问题。

管理菜单只在操作时运行，退出后没有面板进程。节点由单个 `sing-box` 进程运行；公网订阅 URL 由可选的 Python 标准库轻量订阅服务（`nodelite-sub`）提供，无节点时自动停止。不安装 Node.js、Docker、数据库、Nginx、Grafana，也不自动开启大缓冲、BBR 或 swap。Python 3 使用标准库，无 pip 依赖。

## 启动与旧版迁移

安装后，在 VPS 的 SSH 终端输入：

```sh
nl
```

`NL` 也能打开同一个菜单。程序目录是 `/opt/nodelite`，配置目录是 `/etc/nodelite`，代理核心服务是 `nodelite`，订阅服务是 `nodelite-sub`。系统原有的文本行号工具仍保留，通过 `/usr/bin/nl` 调用。

已有 SubProgress Lite 的 VPS：上传下方的新安装包并执行，安装器会迁移旧版配置，保留节点凭据和订阅令牌。升级后使用 `nl`，旧 `subprogress` 命令仅用于兼容原有使用习惯。不要为更名重新创建节点。

安装迁移会重启相关服务；Cloudflare 临时隧道可能因此换域名。完成后用 `nl links` 核对当前 URL，若域名变化，请在客户端替换订阅地址。

## 给 VPS 安装

### 方式 1：一行命令下载安装

```sh
curl -fsSL https://raw.githubusercontent.com/qingyechan/NodeLite/main/dist/nodelite.run -o /root/nodelite.run && sh /root/nodelite.run
```

### 方式 2：上传安装包执行

1. 用 SSH 软件的文件面板，把本项目 `dist/nodelite.run` 上传到 VPS 的 `/root/`。
2. 在 VPS 终端执行：

   ```sh
   sh /root/nodelite.run
   ```

3. 新安装时输入 `1` 创建节点。第一次优先选 VLESS Reality，不需要自己购买域名或手填 UUID。以后输入 `nl` 或 `NL` 即可重新打开菜单。

安装包包含管理程序，代理核心从官方 GitHub 下载并核对固定 SHA-256。可用本地 `dist/nodelite.run.sha256` 校对文件。

支持 Linux + systemd/OpenRC，amd64、arm64、armv7、386 的官方下载包。Python 至少 3.9；包管理器支持 apt、apk、dnf/yum。无 init 的容器会在修改前停止。

## 四类端口明确区分（小白指引）

工具在创建节点、修改端口和配置订阅时，均严格区分并校验以下四类端口：

| 端口类型 | 映射协议类型 | 用途 | 填写规则（NAT 小鸡傻瓜式对照） |
|---|---|---|---|
| **1. SSH 登录端口** | **TCP** | 远程登录管理 VPS（如公网 `23932` → 内部 `22`） | ❌ **绝不能填到节点或订阅中**（工具会自动拦截防误填） |
| **2. 节点公网端口** | **TCP 优先**（无 UDP 先用 TCP） | 手机/电脑客户端实际连接的外部端口 | 普通 VPS 与内部端口相同；NAT 小鸡填商家映射表左边的公网端口（如 `53440`） |
| **3. 节点内部端口** | **TCP 优先**（无 UDP 先用 TCP） | VPS 内 `sing-box` 监听的端口 | 支持 `443`（或 `80`）及 `1024–65535`；NAT 小鸡填同一行映射右边的内部端口（如 `10086`） |
| **4. 在线订阅端口** | **TCP** | 公网自动更新订阅 URL 专用端口 | 必须与 SSH 端口、节点端口分开，单独占一行 TCP 映射（如公网 `40187` → 内部 `20000`） |

- **没有 UDP 就先用 TCP**：VLESS Reality / VMess / Trojan / Shadowsocks 2022 **只需要 TCP 映射**；只有 Hysteria2 / TUIC 才需要 UDP 映射。如果商家后台没有标注 UDP，请直接选 `1. VLESS Reality`（先用 TCP）。
- 菜单 `8`（或 `nl port --node 名称 --port 新内部端口 --public-port 新公网端口`）可在保留原 UUID、密码和 Reality 密钥的前提下直接修改节点端口。

## 分享链接、文件导出与公网自动更新订阅 URL

- **菜单 `2`（查看单节点分享链接）**：输出标准 `vless://`、`trojan://`、`ss://`、`vmess://`、`hysteria2://`、`tuic://` 链接，若已开启公网订阅会一并展示订阅 URL。
- **菜单 `3`（导出本地配置文件）**：在 `/etc/nodelite/exports/` 生成 `flclash.yaml`、`links.txt`、`subscription.txt`，供 SFTP 下载导入。
- **菜单 `4`（开启 / 管理公网自动更新订阅 URL）**：
  - 启动轻量标准库订阅服务 `nodelite-sub`，支持：
    - FlClash / Clash Meta (Mihomo) 订阅：`http(s)://地址:公网端口/s/<令牌>/flclash.yaml`（兼容 `/clash.yaml`）
    - 通用 Base64 订阅（v2rayN / Shadowrocket / Nekobox）：`http(s)://地址:公网端口/s/<令牌>/links.txt`
    - 纯文本 URI 列表：`http(s)://地址:公网端口/s/<令牌>/raw.txt`
    - 版本校验清单：`http(s)://地址:公网端口/s/<令牌>/manifest.json`
  - **自动同步**：新增节点、改名、修改端口、删除节点时，会自动通过原子目录指针刷新订阅快照，无需重启订阅进程；删除最后一个节点后自动停止订阅服务。
  - **访问令牌与 HTTPS**：支持自有域名证书 HTTPS、自签证书 HTTPS 或 HTTP，支持一键重置访问令牌（使旧链接立即 404 失效），并自动兼容迁移前的旧订阅令牌。

## 维护、核心升级与旧服务清理

- **菜单 `10`（梳理 / 备份并清理旧版残留服务）**：自动检测 `nodepilot-sing-box`、`subprogress-auto`、`subprogress-sub`、`nodepilot-subscription` 的运行状态、PID 与内存占用，先完整备份并提取旧订阅令牌，再停止并禁用已确认归属的旧服务。旧服务使用原名识别；具体备份目录以菜单输出为准。
- **菜单 `11`（升级 / 校验 sing-box 核心）**：支持 `amd64`、`arm64`、`armv7`、`386` 架构的 SHA-256 严格校验，替换前用新核心预检现有 `config.json`，升级后对全部节点执行真实协议自测，任何一步失败均自动回滚至 `sing-box.bak`。

## 开发与验证

```sh
python -B terminal/build.py
python -B -m unittest discover -s terminal/tests -v
```

`terminal/tests/live_protocols.py` 是 Linux 隔离实测：仅监听回环随机端口，不修改已有服务；设置 `LITE_TEST_MIHOMO` 可以启用第二套核心的交叉验证，设置 `LITE_TEST_STRESS_ROUNDS` 可执行并发持续负载测试。


## 研究依据

本版没有复制其他项目的安装代码，借鉴的是交互和运行架构：

| 项目 | 借鉴点 | 本版的取舍 |
| --- | --- | --- |
| [3x-ui](https://github.com/MHSanaei/3x-ui) | 集中管理节点/用户、导出客户端参数、服务管理 | 用按需终端菜单，省掉常驻 Web 面板、数据库和历史统计 |
| [233boy/sing-box](https://github.com/233boy/sing-box) | 默认 Reality、终端增删改查、多协议 | 单核心覆盖六协议，专门区分 NAT 公网/内部端口 |
| [v2ray-agent](https://github.com/mack-a/v2ray-agent) | 菜单式部署、证书和分享入口 | 用单核心承载节点，支持本地导出与轻量订阅服务 |
| [XTLS/Xray-install](https://github.com/XTLS/Xray-install) | 官方核心与服务管理分离 | 固定版本、HTTPS 下载、SHA-256 校验、独立命名空间 |
| [sing-box 配置文档](https://sing-box.sagernet.org/configuration/) | 六种协议的服务端与客户端配置 | 由真实核心校验，不靠手工推测“配置看起来正确” |

3x-ui 是功能完整的面板，不能仅凭用户报告断言所有版本都必然占用多少内存；这里没有做同机同负载对照跑分。
