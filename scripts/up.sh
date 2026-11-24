#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

use_proxy=0
if [ "${1:-}" = "--https" ] || [ "${1:-}" = "--proxy" ]; then
  use_proxy=1
elif [ -n "${1:-}" ]; then
  echo "用法: ./scripts/up.sh [--https]" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "未找到 docker。请先安装 Docker，并确认 docker compose 可用。" >&2
  exit 1
fi

if [ ! -f .env ]; then
  ./scripts/init-env.sh
fi

if [ "$use_proxy" -eq 1 ]; then
  docker compose --profile proxy up -d --build
  docker compose --profile proxy ps
  domain=$(awk -F= '$1=="MONITOR_DOMAIN" { print $2; exit }' .env)
  echo
  echo "HTTPS 代理已启动。确认 ${domain} 已解析到本机后访问 https://${domain}"
else
  docker compose up -d --build
  docker compose ps
  echo
  echo "管理界面：http://127.0.0.1:8080"
fi
echo "首次部署时，管理员密码只在生成 .env 时显示一次。"
