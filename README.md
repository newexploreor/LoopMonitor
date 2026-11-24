# LoopMonitor

LoopMonitor 是与 LoopForge 配套使用的轻量监控平台。通过域名或完整 HTTP/HTTPS URL 添加目标，由 Worker 主动探测，展示可用率、响应时间和故障事件，并在故障或恢复时发送 Webhook。

初版包含：

- 单管理员登录、安全 Cookie 和 CSRF 防护
- 监控目标的新增、编辑、暂停、删除和立即检测
- HTTP GET / HEAD / POST、请求头、响应断言
- 定时调度、并发上限、同一目标不重叠执行
- 连续失败达到阈值后产生一条故障事件，恢复后关闭
- 总览、历史明细、24 小时 / 7 天 / 30 天可用率和响应时间
- TLS 证书到期检查与提醒
- Webhook 签名、失败退避重试
- 出站 SSRF 防护：默认拒绝私网、回环、链路本地和云元数据地址
- SQLite 持久化、迁移、保留清理，以及使用 SQLite Backup API 的备份恢复

## 目录

```text
frontend/     React + TypeScript + Vite + Ant Design
backend/      FastAPI、检测器、调度器和 Alembic
deploy/       Caddy 反向代理示例
compose.yaml  本地与服务器部署
```

## 一键部署

需要 Docker 与 Docker Compose。在仓库根目录执行：

```bash
./scripts/up.sh
```

脚本会在缺少 `.env` 时生成应用密钥、凭证加密密钥和管理员密码，然后构建并启动迁移、后端、Worker 和前端。密码只在终端显示一次。生产环境不要把 `.env` 提交到 Git。

本地管理界面是 `http://127.0.0.1:8080`。后端只绑定在 `127.0.0.1:8000`，不直接对公网开放。浏览器通过前端同源访问 `/api`。

只想生成环境文件、暂不启动容器时，执行 `./scripts/init-env.sh`。已有 `.env` 不会被覆盖。

本地 HTTP 访问时 `.env.example` 里的 `COOKIE_SECURE=false`。正式域名启用 HTTPS 后改为 `true`，否则浏览器不会保存登录 Cookie。

## 域名与 HTTPS

1. 准备一台运行 Docker 的 Linux 服务器，优先与被监控服务分开。
2. 把监控域名的 A 记录指向服务器公网地址。
3. 放行 TCP 80 和 443。
4. 在 `.env` 设置 `MONITOR_DOMAIN`，并把 `COOKIE_SECURE=true`。
5. 一键启动带代理的组合：

```bash
./scripts/up.sh --https
```

Caddy 把 `/api` 转到后端，其余路径转到前端，并申请证书。如果宿主机已经占用 80/443，不要再启动 `proxy`，改由现有反向代理转发到 `127.0.0.1:8080`。

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `APP_SECRET_KEY` | 会话签名，至少 32 个字符。生产环境为空时拒绝启动 |
| `CREDENTIAL_ENCRYPTION_KEY` | 32 字节 base64，用于加密请求头、请求体和 Webhook 密钥 |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | 首次创建管理员。密码至少 12 位，不会写入镜像 |
| `DATABASE_URL` | 默认 `sqlite:////data/loopmonitor.db` |
| `MAX_CONCURRENT_CHECKS` | 全局探测并发，默认 10 |
| `ALLOW_PRIVATE_TARGETS` | 默认 false。不能只靠这个开关放开全部私网 |
| `PRIVATE_TARGET_ALLOWLIST` | 明确的 `主机:端口` 或 `网段:端口`，例如 `10.0.0.8:443` |
| `CHECK_RETENTION_DAYS` | 检测记录保留天数，默认 30 |
| `INCIDENT_RETENTION_DAYS` | 已恢复事件保留天数，默认 90 |

生成密钥：

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
```

内网目标必须同时打开 `ALLOW_PRIVATE_TARGETS` 并写入白名单。`169.254.169.254` 等云元数据地址始终拒绝。

## 备份与恢复

备份使用 SQLite Backup API，避免直接复制正在写入的数据库文件而漏掉 WAL。

```bash
docker compose exec backend python -m app.cli backup /data/loopmonitor-backup.db
docker compose cp backend:/data/loopmonitor-backup.db ./loopmonitor-backup.db
```

恢复前先停止服务，再替换数据库：

```bash
docker compose stop backend worker
docker compose cp ./loopmonitor-backup.db backend:/data/restore.db
docker compose run --rm --no-deps backend python -m app.cli restore /data/restore.db
docker compose start backend worker
```

加密密钥要和数据库分开保管。只有数据库、没有 `CREDENTIAL_ENCRYPTION_KEY` 时，历史请求头和 Webhook 密钥无法解密。

## 升级、日志和停止

```bash
git pull
docker compose up -d --build
docker compose logs -f backend worker
docker compose stop
docker compose down
```

`docker compose down` 不会删除数据卷。确认要清空数据时才执行 `docker compose down -v`。数据库迁移由 `migrate` 服务在后端和 Worker 启动前单独执行。

## 开发与测试

```bash
cd backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
python -m app.cli bootstrap
uvicorn app.main:app --reload --port 8000
```

```bash
cd frontend
npm install
npm test
npm run build
npm run dev
```

前端开发服务器把 `/api` 代理到 `http://127.0.0.1:8000`。

GitHub Actions 草案在 `deploy/ci.yml`。把它复制到 `.github/workflows/ci.yml` 后，会在推送和 PR 上运行后端测试与前端构建。写入这个路径需要带 `workflow` 权限的令牌。

可用率只统计实际执行且有效的自动检测：成功次数 / 有效自动检测次数。窗口内没有样本时返回空值，界面显示 `--`。手动检测单独计数。暂停、漏跑和检测器内部错误不进入分母。超时耗时不计入成功请求的平均响应时间。

## 安全说明

- 不内置公开默认密码。
- 密码使用 Argon2id。会话 Cookie 为 HttpOnly、SameSite=Lax，生产 HTTPS 下启用 Secure。
- 变更请求需要 CSRF 令牌。
- 探测、立即检测、测试连接、Webhook 和证书检查使用同一套出站策略，并把连接绑定到已校验的 IP，保留原始 Host 和 SNI。
- 响应和日志不回显 Authorization、Cookie、密钥或带敏感参数的 URL。
