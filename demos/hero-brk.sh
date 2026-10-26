#!/usr/bin/env bash
# Hero GIF 专用的 brk 包装:
#   deps  -> 先放一个 scanning 动画,再秒出镜头外预抓取的真实结果(无联网死等)
#   其它  -> 跑真实 CLI
# 预抓取素材见 demos/.hero/deps.ansi(由 `script` 捕获的真实彩色输出)。
HERE="$(cd "$(dirname "$0")" && pwd)"
case "$1" in
  deps)
    printf '\033[36m⠋\033[0m scanning dependencies'
    for f in ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏; do printf '\r\033[36m%s\033[0m querying OSV + EPSS   ' "$f"; sleep 0.07; done
    printf '\r\033[2K'
    cat "$HERE/.hero/deps.ansi"
    ;;
  secrets)
    shift
    exec node "$HERE/../bin/brk.js" secrets "$@"
    ;;
  *)
    exec node "$HERE/../bin/brk.js" "$@"
    ;;
esac
