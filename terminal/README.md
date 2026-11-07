# NodeLite 终端说明文档

在 Linux VPS 的 SSH 终端输入 `nl`（或 `NL`），可通过中文数字菜单完成创建节点、复制分享链接、导出配置文件、开启在线订阅服务、修改节点端口、改名、删除、升级核心、清理旧版残留服务、协议自测及连接排障。

管理菜单仅在操作时运行，退出后无后台面板进程。代理节点由单个 `sing-box` 进程承载；在线订阅服务由基于 Python 3 标准库的轻量 HTTP/HTTPS 服务（`nodelite-sub`）提供，无节点时自动停止。整个工具链仅依赖 Python 3 标准库，不安装 Node.js、Docker、数据库、Nginx 或第三方 Python 包。

---

## 运行目录与旧版本迁移

安装完成后，在终端输入以下命令打开主菜单：

```sh
nl
```

输入大写 `NL` 同样有效。相关目录与服务名称如下：

- 程序目录：`/opt/nodelite`
- 配置与快照目录：`/etc/nodelite`
- 代理核心服务名：`nodelite`
- 在线订阅服务名：`nodelite-sub`
- 系统原有的文本行号工具仍保留在 `/usr/bin/nl`，不受影响。

若服务器上已安装旧版 SubProgress Lite，直接执行新安装包即可自动迁移原有节点凭据与订阅访问令牌，无需重新创建节点。若此前启用了免域名的 Cloudflare 临时隧道，服务重启后临时域名会重新生成，可通过 `nl links` 查看最新订阅地址。

---

## 安装方式

### 方式一：命令行在线安装

```sh
curl -fsSL https://raw.githubusercontent.com/qingyechan/NodeLite/main/dist/nodelite.run -o /root/nodelite.run && sh /root/nodelite.run
```

### 方式二：上传安装包执行

1. 将本仓库 `dist/nodelite.run` 上传至服务器的 `/root/` 目录。
2. 在服务器终端执行：

   ```sh
   sh /root/nodelite.run
   ```

3. 首次安装后按提示选择 `1` 创建节点。常规环境下推荐优先选择 `VLESS Reality`，无需自备域名，程序会自动测速选择握手域名并生成凭据。

安装包内置管理脚本，代理核心从官方 GitHub Release 下载并严格校验 SHA-256 摘要。支持 `systemd` 与 `OpenRC` 服务管理，支持 `amd64`、`arm64`、`armv7`、`386` 架构，要求 Python 3.9 及以上版本。

---

## 端口类型与填写规范

程序在创建节点、修改端口与配置在线订阅时，会对以下四类端口进行区分与冲突校验：

| 端口类型 | 传输协议 | 作用说明 | 填写规范 |
| :--- | :--- | :--- | :--- |
| **1. SSH 登录端口** | TCP | 远程登录管理服务器（如公网 `23932` 映射至内部 `22`） | 不可用于节点或订阅配置，程序会自动识别并拦截 |
| **2. 节点公网端口** | TCP / UDP | 客户端实际连接的外部端口 | 独立 IP 服务器与内部端口一致；NAT 服务器填写后台映射表中的外部（公网）端口 |
| **3. 节点内部端口** | TCP / UDP | 服务器内部 `sing-box` 实际监听的端口 | 支持 `443`、`80` 及 `1024–65535`；NAT 服务器填写同一条映射规则对应的内部端口 |
| **4. 在线订阅端口** | TCP | 在线自动更新订阅服务专用端口 | 需与 SSH 端口及节点端口分开，在 NAT 服务器上需单独占用一条 TCP 映射规则 |

- **协议选择建议**：VLESS Reality、VMess、Trojan、Shadowsocks 2022 仅需 TCP 端口映射；Hysteria2 与 TUIC 需 UDP 端口映射。若 NAT 服务器后台未提供 UDP 转发规则，请选择基于 TCP 的协议。
- **修改端口**：通过菜单 `8`（或命令 `nl port --node 名称 --port 新内部端口 --public-port 新公网端口`）可在保留原有 UUID、密码与密钥的前提下直接更新端口。

---

## 分享链接、本地导出与多客户端在线订阅

- **菜单 `2`（查看单节点分享链接）**：输出标准 `vless://`、`vmess://`、`hysteria2://`、`tuic://`、`trojan://`、`ss://` 链接；若已启用在线订阅，会一并显示订阅地址。
- **菜单 `3`（导出本地配置文件）**：在 `/etc/nodelite/exports/` 下生成 `flclash.yaml`、`links.txt` 与 `subscription.txt`，可通过 SFTP 下载至本地导入客户端。
- **菜单 `4`（开启 / 管理在线订阅服务）**：
  - 启动轻量订阅服务 `nodelite-sub`，根据客户端 `User-Agent` 或路径后缀返回对应格式：
    - Clash / Mihomo 系列（FlClash、Clash Verge Rev、Clash Party、CFW、Stash 等）：`http(s)://地址:公网端口/s/<令牌>/flclash.yaml`（兼容 `/clash.yaml` 与 `/sub`）
    - 通用 Base64 订阅（v2rayN、v2rayNG、Shadowrocket、NekoBox、Quantumult X、Loon、Streisand 等）：`http(s)://地址:公网端口/s/<令牌>/links.txt`
    - Sing-box 官方客户端配置（SFA / SFI / SFM）：`http(s)://地址:公网端口/s/<令牌>/singbox.json`
    - 纯文本 URI 列表：`http(s)://地址:公网端口/s/<令牌>/raw.txt`
    - 快照校验清单：`http(s)://地址:公网端口/s/<令牌>/manifest.json`
  - **快照同步机制**：节点新增、改名、修改端口或删除时，通过原子目录切换自动更新订阅快照，无需重启订阅进程；当节点全部清空时自动停止订阅服务。
  - **令牌与安全控制**：支持 HTTP、自有域名证书 HTTPS、自签证书 HTTPS 以及 Cloudflare 隧道（固定命名隧道、CDN 回源或免域名临时隧道）；支持随时重置访问令牌，使旧订阅地址立即失效。

---

## 维护、核心升级与旧服务清理

- **菜单 `10`（梳理并清理旧版残留服务）**：自动检测历史遗留服务（如 `nodepilot-sing-box`、`subprogress-auto`、`subprogress-sub`、`nodepilot-subscription`）的运行状态、PID 与内存占用，先备份配置文件并提取旧订阅令牌，随后按确认结果停用对应旧服务。
- **菜单 `11`（升级 / 校验 sing-box 核心）**：下载对应架构的核心压缩包并校验 SHA-256，替换前使用新核心校验现有配置文件，替换后对全部节点执行真实协议回环自测；若任一步骤异常则自动恢复备份核心。
- **菜单 `15`（外部节点汇总与链式代理）**：支持解析并添加其他服务器的节点链接，或配置 `dialer-proxy` 前置中转与落地链式代理。
- **菜单 `16`（GitHub 在线更新）**：从官方仓库拉取最新 `nodelite.run` 与 `.sha256` 校验文件，校验通过后原子替换管理脚本。

---

## 构建与测试

```sh
python -B terminal/build.py
python -B -m unittest discover -s terminal/tests -v
```

`terminal/tests/live_protocols.py` 用于在 Linux 环境下执行六协议本地回环隔离实测（仅监听 `127.0.0.1` 随机端口，不改动现有系统服务）。

---

## 架构参考与设计取舍

本项目代码独立实现，在交互形式与功能边界上参考了以下开源项目的经验并做了轻量化取舍：

| 参考项目 | 借鉴思路 | 本项目的取舍 |
| :--- | :--- | :--- |
| [3x-ui](https://github.com/MHSanaei/3x-ui) | 集中管理节点、导出客户端配置、服务状态管理 | 采用按需运行的终端菜单，省去常驻 Web 面板、数据库与流量统计后台 |
| [233boy/sing-box](https://github.com/233boy/sing-box) | 默认 Reality 协议、终端增删改查、多协议管理 | 单核心承载六种常用协议，增加针对 NAT 服务器公网与内部端口的区分校验 |
| [v2ray-agent](https://github.com/mack-a/v2ray-agent) | 交互式部署引导、证书与订阅输出 | 使用单核心管理节点，同时提供本地文件导出与标准库轻量订阅服务 |
| [XTLS/Xray-install](https://github.com/XTLS/Xray-install) | 核心二进制与服务配置分离管理 | 固定核心版本、HTTPS 下载、SHA-256 严格校验与失败自动回滚 |
| [sing-box 官方文档](https://sing-box.sagernet.org/configuration/) | 各协议服务端与客户端标准配置结构 | 每次变更均由核心预检并配合真实协议握手自测验证 |
