# NodeLite（轻节点）

**在终端里，把 VPS 变成可用节点。**

轻量的 Linux VPS 节点部署与订阅管理工具。在 VPS 终端输入 `nl`（或 `NL`），通过中文数字菜单完成：**三步创建节点、复制分享链接、导出 FlClash 配置、开启公网自动更新订阅 URL（支持固定 Cloudflare 命名隧道/自有域名）、修改节点端口（含 443）、改名、删除、恢复上一版配置、升级核心、清理旧服务、自测或排查连接问题**。

- **按需运行、低内存常驻**：管理菜单仅在操作时运行，退出后释放内存；节点由单个 `sing-box 1.14.4` 进程承载（默认软目标 `32 MiB`），公网订阅由可选的 Python 3 标准库轻量服务（`nodelite-sub`）提供，无节点时自动停止，专为 128 MB+ 小内存 VPS / NAT 小鸡优化。
- **零外部运行时依赖**：仅使用 Python 3 标准库，不安装 Node.js、Docker、数据库、Nginx 或常驻 Web 面板。
- **真协议实测与失败自动回滚**：每次变更先通过 `sing-box check` 语法校验，再通过真实协议握手访问 HTTPS 204 页验证出站，任何一步失败均自动恢复上一版配置。

---

## 一键安装与启动

在 Linux VPS 的 `root` 终端执行以下命令（支持 Debian / Ubuntu / Alpine / Rocky / Alma / CentOS，架构支持 `amd64` / `arm64` / `armv7` / `386`，需 `systemd` 或 `OpenRC`）：

### 方式 1：GitHub 一行命令安装

```sh
curl -fsSL https://raw.githubusercontent.com/qingyechan/NodeLite/main/dist/nodelite.run -o /root/nodelite.run && sh /root/nodelite.run
```

### 方式 2：离线上传安装

将本仓库 `dist/nodelite.run` 上传至 VPS 的 `/root/` 目录后执行：

```sh
sh /root/nodelite.run
```

---

## 日常使用（输入 `nl` 或 `NL`）

安装完成后，随时在 VPS 终端输入 `nl` 或 `NL` 打开中文菜单，也支持直接带参数运行：

```sh
nl              # 打开中文数字交互菜单（输入 NL 同样有效）
nl links        # 查看所有节点分享链接、四阶段验证状态与自动更新订阅 URL
nl export       # 导出本地 flclash.yaml / links.txt / subscription.txt
nl test         # 对所有节点执行服务器内部真实协议自测
nl doctor       # 查看整套服务内存明细、证书剩余天数、端口监听与四步排障指引
nl rollback     # 一键恢复上一版保存的节点配置
```

---

## 目录结构

```text
NodeLite/
├── .github/workflows/ci.yml     # GitHub Actions 自动化 Linux 测试与 Release 发布
├── dist/
│   ├── nodelite.run             # 独立自包含 Linux 安装包（由 terminal/build.py 生成）
│   └── nodelite.run.sha256      # 安装包 SHA-256 校验值
└── terminal/
    ├── nodelite.py              # 中文交互菜单（14 项功能）与 CLI 入口
    ├── protocols.py             # 六协议配置、分享链接、FlClash YAML 与订阅快照打包
    ├── runtime.py               # 事务提交回滚、协议自测、轻量订阅与转发服务、核心升级、旧服务清理、网络诊断
    ├── install.sh               # Linux 安装脚本模板
    ├── build.py                 # 打包生成 dist/nodelite.run
    ├── README.md                # 详细端口规则、可靠性设计与架构说明
    └── tests/
        ├── test_terminal.py     # 26 项单元与事务集成测试
        └── live_protocols.py    # Linux 回环真机六协议隔离实测与持续负载压测
```

---

## 开发与测试

```sh
python -B terminal/build.py
python -B -m unittest discover -s terminal/tests -v
```

详细端口填写指引、NAT 小鸡映射规则与设计说明见 [terminal/README.md](terminal/README.md)。
