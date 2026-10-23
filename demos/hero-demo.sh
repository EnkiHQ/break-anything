#!/usr/bin/env bash
# Break Anything — Hero GIF 录制脚本
# 用 asciinema 录这个脚本,再转成 GIF。全程只打自有/样例靶子。
# 用法:asciinema rec hero.cast -c "bash demos/hero-demo.sh"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRK="node $ROOT/bin/brk.js"

# 模拟"敲命令"的节奏:打印提示符 + 命令,停顿,再执行
type_run() {
  printf '\033[1;32m$\033[0m %s\n' "$1"
  sleep 1.2
  eval "$2"
  echo
  sleep 1.8
}

clear
printf '\033[1;36m# Break Anything — 在别人动手之前,先攻破你自己的项目\033[0m\n\n'
sleep 1.5

# —— 镜头 1:一个你"忘了升级"的依赖 ——
type_run "cat demos/sample-npm/package.json" \
  "cat '$ROOT/demos/sample-npm/package.json'"

# —— 镜头 2:扫出真实 CVE,按"可达性"排序,只给你该管的 ——
type_run "brk deps demos/sample-npm" \
  "$BRK deps '$ROOT/demos/sample-npm' 2>/dev/null || true"

# —— 镜头 3:密钥从代码里删了,但还躺在 git 历史里 ——
printf '\033[1;36m# 你以为删掉就安全了?看看 git 历史。\033[0m\n'
sleep 1.2
TMP="$(mktemp -d)"
(
  cd "$TMP"
  git init -q; git config user.email d@demo.co; git config user.name demo
  echo 'const key="AKIAIOSFODNN7EXAMPLE";' > app.js
  git add app.js; git commit -qm "add config"
  echo 'const key=process.env.AWS_KEY;' > app.js
  git add app.js; git commit -qm "move key to env"
)
type_run "brk secrets $TMP --history" \
  "$BRK secrets '$TMP' --history 2>/dev/null || true"
rm -rf "$TMP"

printf '\033[1;36m# Find → Prove → Fix.  npx break-anything\033[0m\n'
sleep 2.5
