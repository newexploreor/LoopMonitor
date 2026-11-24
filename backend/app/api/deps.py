from __future__ import annotations

import secrets
from collections.abc import Generator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.models import User
from app.security import load_session, session_error


def get_db(request: Request) -> Generator[Session, None, None]:
    session = request.app.state.SessionLocal()
    try:
        yield session
    finally:
        session.close()


def current_user(request: Request, session: Session = Depends(get_db)) -> User:
    token = request.cookies.get("lm_session")
    if not token:
        raise HTTPException(status_code=401, detail="未登录")
    settings = request.app.state.settings
    try:
        data = load_session(settings.app_secret_key, token, settings.session_seconds)
    except Exception as exc:
        if session_error(exc):
            raise HTTPException(status_code=401, detail="未登录") from exc
        raise HTTPException(status_code=401, detail="未登录") from exc
    user = session.get(User, data.get("uid"))
    if user is None:
        raise HTTPException(status_code=401, detail="未登录")
    return user


def csrf_protect(request: Request) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    cookie = request.cookies.get("lm_csrf") or ""
    header = request.headers.get("x-csrf-token") or ""
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF 校验失败")
