#!/usr/bin/env bash
# 为 Hero GIF 准备一个临时 git 仓库:提交一个密钥,再把它从代码里删掉
# —— 制造"代码里删了、历史里还在"的演示场景。全程本地,不联网。
set -e
D=/tmp/brk-hero
rm -rf "$D"; mkdir -p "$D"; cd "$D"
git init -q
git config user.email demo@demo.co
git config user.name demo
echo 'const key = "AKIAIOSFODNN7EXAMPLE";' > app.js
git add app.js && git commit -qm "add config"
echo 'const key = process.env.AWS_KEY;' > app.js
git add app.js && git commit -qm "move key to env var"
