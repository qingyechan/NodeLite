#!/bin/sh
set -eu
umask 077
export DEBIAN_FRONTEND=noninteractive
fail() { printf '\n安装未完成：%s\n' "$*" >&2; exit 1; }
retry() { tries=0; until "$@"; do tries=$((tries+1)); [ "$tries" -lt 3 ] || return 1; sleep 2; done; }
[ "$(id -u)" = 0 ] || fail '请使用 root，或 sudo sh nodelite.run'
[ "$(uname -s)" = Linux ] || fail '仅支持 Linux VPS'
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; hash=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968 ;;
  aarch64|arm64) arch=arm64; hash=436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26 ;;
  armv7l) arch=armv7; hash=fd164ed45ebc784f657a3e1d0e0ad0f68afdcff864ee57122c2cfed3ddb80a00 ;;
  i386|i686) arch=386; hash=efb46daaa48ee55e090bd1dfcaee34bfbe9bdbd9b89fa9f328d25f81a619e865 ;;
  *) fail '支持 amd64、arm64、armv7、386 架构' ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  init=systemd
elif command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; then
  init=openrc
else
  fail '需要正在运行的 systemd 或 OpenRC，不支持没有 init 的容器'
fi
printf 'NodeLite（轻节点）：%s / %s。不会安装网页面板，也不会改动其他服务。\n' "$arch" "$init"
root=/opt/nodelite
[ ! -L "$root" ] || fail '安装目录不能是符号链接'
mkdir -p "$root"
chmod 700 "$root"
mkdir "$root/.install-lock" 2>/dev/null || fail '另一个安装任务正在运行'
work=$(mktemp -d "$root/.install.XXXXXX") || { rmdir "$root/.install-lock"; fail '磁盘空间不足，不能创建安装目录'; }
cleanup() {
  code=$?
  trap - EXIT HUP INT TERM
  case "$work" in /opt/nodelite/.install.*) rm -rf -- "$work" ;; esac
  rmdir "$root/.install-lock" 2>/dev/null || true
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
printf '1/4 检查运行依赖……\n'
missing=0
for cmd in python3 curl openssl tar sha256sum ss; do command -v "$cmd" >/dev/null 2>&1 || missing=1; done
if [ "$missing" = 1 ]; then
  if command -v apk >/dev/null 2>&1; then
    retry apk add --no-cache python3 curl openssl ca-certificates tar iproute2 gcompat || fail 'Alpine 软件源不可用'
  elif command -v apt-get >/dev/null 2>&1; then
    retry apt-get -o DPkg::Lock::Timeout=30 update || fail 'apt 软件源不可用'
    retry apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends python3 curl openssl ca-certificates tar iproute2 || fail '依赖安装失败'
  elif command -v dnf >/dev/null 2>&1; then
    retry dnf install -y python3 curl openssl ca-certificates tar iproute || fail '依赖安装失败'
  elif command -v yum >/dev/null 2>&1; then
    retry yum install -y python3 curl openssl ca-certificates tar iproute || fail '依赖安装失败'
  else
    fail '请先安装 python3 curl openssl ca-certificates tar iproute2，再重新运行'
  fi
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' || fail '需要 Python 3.9 或以上版本'
printf '2/4 下载固定版本代理核心并核对 SHA-256……\n'
version=1.14.4
need_core=1
if [ ! -x "$root/sing-box" ] && [ -x /opt/subprogress-lite/sing-box ] && /opt/subprogress-lite/sing-box version 2>/dev/null | head -n 1 | grep -q "version $version$"; then
  cp -f /opt/subprogress-lite/sing-box "$root/sing-box"
  chmod 700 "$root/sing-box"
fi
if [ -x "$root/sing-box" ] && "$root/sing-box" version 2>/dev/null | head -n 1 | grep -q "version $version$"; then
  need_core=0
fi
if [ "$need_core" = 1 ]; then
  url="https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-linux-$arch.tar.gz"
  curl -fL --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 240 "$url" -o "$work/core.tar.gz" || fail 'GitHub 下载失败；检查 VPS 的 DNS/出站网络，稍后重试。未关闭证书验证。'
  printf '%s  %s\n' "$hash" "$work/core.tar.gz" | sha256sum -c - || fail '核心下载校验失败，已停止安装'
  tar -xzf "$work/core.tar.gz" -C "$work" "sing-box-$version-linux-$arch/sing-box"
  chmod 700 "$work/sing-box-$version-linux-$arch/sing-box"
  if ! "$work/sing-box-$version-linux-$arch/sing-box" version >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
      retry apk add --no-cache gcompat || fail '缺少 Alpine 兼容运行库'
    fi
  fi
  "$work/sing-box-$version-linux-$arch/sing-box" version >/dev/null || fail '核心不能运行，未安装'
  for cfg in /etc/nodelite/current/config.json /etc/subprogress-lite/current/config.json; do
    if [ -f "$cfg" ]; then
      "$work/sing-box-$version-linux-$arch/sing-box" check -c "$cfg" || fail '现有节点配置与新核心不兼容，已保留原核心'
    fi
  done
  if [ -x "$root/sing-box" ]; then
    cp -f "$root/sing-box" "$root/sing-box.bak"
    chmod 700 "$root/sing-box.bak"
  fi
  mv "$work/sing-box-$version-linux-$arch/sing-box" "$root/sing-box"
fi
printf '3/4 安装终端菜单（支持 nl / NL 启动）……\n'
# Replaced by build.py with a self-contained, checksummed source archive.
__PAYLOAD__
python3 - "$work" "$root" <<'PY'
import base64, hashlib, io, os, pathlib, sys, tarfile
work, root = map(pathlib.Path, sys.argv[1:])
data = base64.b64decode((work/'payload.b64').read_bytes())
if hashlib.sha256(data).hexdigest() != PAYLOAD_SHA256:
    raise SystemExit('菜单文件校验失败')
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    for name in ['nodelite.py', 'runtime.py', 'protocols.py']:
        member = archive.getmember(name)
        if not member.isfile(): raise SystemExit('非法安装包')
        target = root/(name+'.new')
        target.write_bytes(archive.extractfile(member).read())
        target.chmod(0o600)
        # Syntax check before replacing the existing manager.
        compile(target.read_bytes(), name, 'exec')
    for name in ['nodelite.py', 'runtime.py', 'protocols.py']:
        os.replace(root/(name+'.new'), root/name)
PY
mkdir -p /etc/nodelite /usr/local/bin
chmod 700 /etc/nodelite
cat > "$work/launcher" <<'SH'
#!/bin/sh
# NodeLite managed launcher
exec python3 -B /opt/nodelite/nodelite.py "$@"
SH
chmod 755 "$work/launcher"
for cmd_name in nl NL nodelite subprogress; do
  target="/usr/local/bin/$cmd_name"
  if [ ! -e "$target" ] || grep -qE 'NodeLite managed launcher|/opt/(nodelite|subprogress-lite)/' "$target" 2>/dev/null; then
    cp -f "$work/launcher" "$target"
    chmod 755 "$target"
  fi
done
rm -f "$work/launcher"
printf '4/4 注册独立服务并检查旧版迁移……\n'
if [ "$init" = systemd ]; then
  cat > "$work/service" <<'UNIT'
[Unit]
Description=NodeLite proxy core
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
Type=simple
Environment=GOMEMLIMIT=32MiB GOGC=50
UMask=0077
ExecStart=/opt/nodelite/sing-box run -c /etc/nodelite/current/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
LimitNOFILE=8192
[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 "$work/service"
  mv "$work/service" /etc/systemd/system/nodelite.service
  systemctl daemon-reload
else
  cat > "$work/service" <<'UNIT'
#!/sbin/openrc-run
name="NodeLite"
description="NodeLite proxy core"
supervisor="supervise-daemon"
command="/opt/nodelite/sing-box"
command_args="run -c /etc/nodelite/current/config.json"
export GOMEMLIMIT=32MiB
export GOGC=50
umask 077
respawn_delay=5
respawn_max=3
respawn_period=60
output_logger="logger -t nodelite"
error_logger="logger -t nodelite"
depend() { need net; }
UNIT
  chmod 755 "$work/service"
  mv "$work/service" /etc/init.d/nodelite
fi
python3 -B /opt/nodelite/runtime.py migrate-old >/dev/null || fail '旧版配置迁移失败，原目录未删除'
printf '\n安装完成。输入 nl 或 NL 打开菜单，选 1 创建节点。\n'
printf '菜单退出后不占用内存；代理核心只在有节点时运行。\n'
if [ "${1:-}" != '--install-only' ] && [ -t 0 ]; then
  nl
fi
