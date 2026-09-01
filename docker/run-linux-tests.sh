#!/usr/bin/env bash
# 在全新 Linux 容器内跑全量测试 + 真实 root 加固/自动提权/并发锁测试。
# 用法（宿主机）：bash docker/run-linux-tests.sh [SDK镜像，默认 dotnet-sdk10:local]
# 每次运行都是全新容器（隔离、可重复），产物不污染宿主。
# 注：镜像经 /tmp/mcr_direct_pull.py 直连 registry 下载 + docker load（绕过 Docker Desktop 代理）。
set -euo pipefail

IMAGE="${1:-dotnet-sdk10:local}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

echo "== 阶段1：普通用户跑全量测试（与 CI 一致；root 分支行为由阶段2覆盖） =="
docker run --rm -v "$REPO":/src:ro "$IMAGE" bash -euo pipefail -c '
  useradd -m tester 2>/dev/null || true
  cp -a /src /work && chown -R tester /work
  rm -rf /work/src/*/obj /work/src/*/bin /work/tests/*/obj /work/tests/*/bin /work/publish /work/dist
  su tester -c "cd /work && dotnet test -v q 2>&1 | tail -4"
'

echo "== 阶段2：真实 root 加固/自动提权安装/并发锁流程 =="
docker run --rm -v "$REPO":/src:ro "$IMAGE" bash -euxo pipefail -c '
  cp -a /src /work && cd /work
  rm -rf src/*/obj src/*/bin tests/*/obj tests/*/bin
  # 工具链：sudo + NativeAOT 前置（clang/zlib）
  APT=""
  command -v sudo >/dev/null || APT="sudo"
  command -v clang >/dev/null || APT="$APT clang zlib1g-dev"
  [ -n "$APT" ] && (apt-get update -qq && apt-get install -y -qq $APT >/dev/null)
  useradd -m -s /bin/bash tester 2>/dev/null || true
  echo "tester ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/tester
  # 按容器架构选 RID（NativeAOT 不支持跨架构交叉编译 Linux）
  case "$(uname -m)" in aarch64) RID=linux-arm64;; *) RID=linux-x64;; esac
  dotnet publish src/HPass.Cli -c Release -r $RID -p:PublishAot=true -o publish 2>&1 | tail -1
  mkdir -p /opt/hpass && cp publish/hpass /opt/hpass/hpass && chmod 755 /opt/hpass/hpass
  ln -sf /opt/hpass/hpass /usr/local/bin/hpass
  export H=/home/tester/.hpass
  run_user() { su tester -c "HPASS_PASSPHRASE=linux-pass-123 $*"; }

  run_user "hpass init --no-harden" >/dev/null
  echo linux-secret-91 | run_user "hpass set db -u root --password-stdin" >/dev/null
  OUT=$(run_user "hpass exec --allow-echo -- sh -c \"echo {{db}}\"")
  [ "$OUT" = "{{db}}" ] || { echo "FAIL: 脱敏 [$OUT]"; exit 1; }

  echo "-- 场景A：真实用户发起 sudo harden（常态路径）"
  su tester -c "sudo -n hpass --home /home/tester/.hpass harden" | tail -1
  su tester -c "test -w $H/vault.json" && { echo "FAIL: 加固后仍可写"; exit 1; } || true
  echo "   目录: $(stat -c %U:%G $H)  vault.json: $(stat -c %U:%G $H/vault.json) $(stat -c %a $H/vault.json)"
  lsattr "$H/vault.json" 2>/dev/null | awk "{print \$1}" | grep -q "i" \
    || echo "   note: 文件系统不支持不可变标志，已降级为属主写保护"
  echo root-secret-77 | run_user "hpass set db3 -u u3 --password-stdin" || { echo "FAIL: 自动提权安装失败"; exit 1; }
  run_user "hpass list --json" | grep -q "db3" || { echo "FAIL: db3 未入库"; exit 1; }
  OUT3=$(run_user "hpass exec --allow-echo -- sh -c \"echo {{db3}}\"")
  [ "$OUT3" = "{{db3}}" ] || { echo "FAIL: root 态脱敏 [$OUT3]"; exit 1; }

  echo "-- 并发写 10 路不丢更新（flock 排队）"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    echo "Conc-Pass-$i" | run_user "hpass set conc-$i --password-stdin" &
  done
  wait
  N=$(run_user "hpass list --json" | grep -c "\"name\": \"conc-")
  [ "$N" = "10" ] || { echo "FAIL: 并发丢更新（$N/10）"; exit 1; }
  echo "   并发条目 10/10"

  echo "-- 场景B：root 直接 harden（管理员路径，不得锁死用户读路径）"
  sudo -n hpass --home /home/tester/.hpass harden >/dev/null 2>&1 || true
  run_user "hpass list --json" >/dev/null && echo "   root 直接 harden 后用户读路径正常" \
    || { echo "FAIL: root 直接 harden 锁死用户"; exit 1; }

  sudo -n chattr -i "$H/vault.json" "$H/master.key" 2>/dev/null || true
  sudo -n rm -rf "$H"
  echo "ALL LINUX FLOW TESTS PASSED"
' 2>&1 | grep -vE "^\+ |debconf|Setting up|Selecting|Preparing|Unpacking"