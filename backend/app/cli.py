from __future__ import annotations

import argparse
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from app.config import get_settings, reset_settings_cache
from app.db import make_engine, make_session_factory
from app.services.maintenance import backup_database, ensure_admin, restore_database, seed_settings


def migrate() -> None:
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(config, "head")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loopmonitor")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-config")
    sub.add_parser("migrate")
    sub.add_parser("ensure-admin")
    sub.add_parser("bootstrap")
    backup = sub.add_parser("backup")
    backup.add_argument("destination")
    restore = sub.add_parser("restore")
    restore.add_argument("source")
    args = parser.parse_args(argv)
    reset_settings_cache()
    settings = get_settings()
    if args.command == "check-config":
        print("配置有效")
        return
    if args.command == "migrate":
        migrate()
        print("数据库迁移完成")
        return
    if args.command == "backup":
        backup_database(settings.database_url, args.destination)
        print(f"已备份到 {args.destination}")
        return
    if args.command == "restore":
        restore_database(settings.database_url, args.source)
        print("数据库已恢复。请在服务停止时执行恢复，然后再启动。")
        return
    if args.command in {"ensure-admin", "bootstrap"}:
        if args.command == "bootstrap":
            migrate()
        engine = make_engine(settings.database_url)
        session = make_session_factory(engine)()
        try:
            seed_settings(session, settings)
            created = ensure_admin(session, settings)
            session.commit()
        finally:
            session.close()
            engine.dispose()
        print("管理员账号已存在" if created == "exists" else "管理员账号已创建")
        return
    parser.error("未知命令")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(str(exc), file=sys.stderr)
        sys.exit(1)
