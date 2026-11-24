#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo ".env 已存在，未覆盖"
  exit 0
fi

rand_b64() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$bytes" | tr -d '\n'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import os,base64,sys; print(base64.b64encode(os.urandom(int(sys.argv[1]))).decode(), end='')" "$bytes"
  else
    echo "需要 openssl 或 python3 来生成密钥" >&2
    exit 1
  fi
}

rand_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr '+/' 'AZ' | tr -d '=\n'
  else
    python3 -c "import secrets; print(secrets.token_urlsafe(18), end='')"
  fi
}

secret=$(rand_b64 48)
key=$(rand_b64 32)
password=$(rand_password)

awk -v secret="$secret" -v key="$key" -v password="$password" '
  BEGIN { FS = OFS = "=" }
  $1 == "APP_SECRET_KEY" { print "APP_SECRET_KEY=" secret; next }
  $1 == "CREDENTIAL_ENCRYPTION_KEY" { print "CREDENTIAL_ENCRYPTION_KEY=" key; next }
  $1 == "ADMIN_PASSWORD" { print "ADMIN_PASSWORD=" password; next }
  { print }
' .env.example > .env
chmod 600 .env

echo "已生成 .env"
echo "管理员初始密码（只显示这一次，请立即保存）：${password}"
