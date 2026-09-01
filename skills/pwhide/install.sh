#!/usr/bin/env bash
# 将 pwhide skill 安装到 Agent 的 skills 目录
# 用法：./install.sh [目标skills目录]   （缺省时按 ~/.claude/skills > ~/.zcode/skills > ~/.agents/skills 自动探测）
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-}"

if [ -z "$DEST" ]; then
  for cand in "$HOME/.claude/skills" "$HOME/.zcode/skills" "$HOME/.agents/skills"; do
    if [ -d "$cand" ]; then
      DEST="$cand"
      break
    fi
  done
fi
if [ -z "$DEST" ]; then
  DEST="$HOME/.claude/skills"
fi

mkdir -p "$DEST"
rm -rf "$DEST/pwhide"
cp -R "$SRC" "$DEST/pwhide"
rm -f "$DEST/pwhide/install.sh"

echo "pwhide skill 已安装到：$DEST/pwhide"
echo "如需项目级安装：cp -r \"$SRC\" <项目>/.claude/skills/"
