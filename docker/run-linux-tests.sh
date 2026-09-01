#!/usr/bin/env bash
# 在全新 Linux 容器内跑全量测试 + 真实 root 加固/自动提权/并发锁/staging 攻击对抗测试。
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

echo "== 阶段2：真实 root 加固/自动提权安装/并发锁/staging 攻击对抗 =="
docker run --rm -v "$REPO":/src:ro "$IMAGE" bash -euxo pipefail -c '
  cp -a /src /work && cd /work
  rm -rf src/*/obj src/*/bin tests/*/obj tests/*/bin
  APT=""
  command -v sudo >/dev/null || APT="sudo"
  command -v clang >/dev/null || APT="$APT clang zlib1g-dev"
  [ -n "$APT" ] && (apt-get update -qq && apt-get install -y -qq $APT >/dev/null)
  useradd -m -s /bin/bash tester 2>/dev/null || true
  echo "tester ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/tester
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

  echo "-- 场景C：staging 轮换攻击对抗（root 专属文件不得经安装落入用户可读库）"
  sudo -n rm -rf "$H" /opt/attack 2>/dev/null || true
  run_user "hpass init --no-harden" >/dev/null
  echo Init-Pass-9x | run_user "hpass set seed --password-stdin" >/dev/null
  su tester -c "sudo -n hpass --home $H harden" >/dev/null
  sudo -n mkdir -p /opt/attack
  echo eyJzZWNyZXQiOiJST09ULVNFQ1JFVC1YWVotOWYzIiwicGFkIjpbMSwyLDNdfQ== | base64 -d | sudo -n tee /opt/attack/secret.json >/dev/null
  sudo -n chmod 600 /opt/attack/secret.json
  sudo -n chmod 700 /opt/attack
  su tester -c "while true; do for f in $H/run/staging/vault.json.*; do [ -e \"\$f\" ] || continue; mv \"\$f\" \"\$f.bak\" 2>/dev/null && ln -sf /opt/attack/secret.json \"\$f\" 2>/dev/null && rm -f \"\$f.bak\" 2>/dev/null; done; done" &
  ATTACKER=$!
  PWNED=0
  for i in $(seq 1 12); do
    echo "Atk-Pass-$i" | run_user "hpass set t$i --password-stdin" >/dev/null 2>&1 || true
    if run_user "hpass list --json" 2>/dev/null | grep -q ROOT-SECRET; then PWNED=1; echo "   [第 $i 次] 泄露！"; break; fi
  done
  kill $ATTACKER 2>/dev/null || true
  if [ "$PWNED" = "1" ]; then echo "FAIL: staging 竞态导致 root 专属文件泄露"; sudo -n rm -rf "$H" /opt/attack; exit 1; fi
  echo "   12 次对抗尝试，root 专属文件未泄露（fd-based 属主复核生效）"
  sudo -n rm -rf "$H" /opt/attack
  echo "ALL LINUX FLOW TESTS PASSED"
' 2>&1 | grep -vE "^\+ |debconf|Setting up|Selecting|Preparing|Unpacking"
