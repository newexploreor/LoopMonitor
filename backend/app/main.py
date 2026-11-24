from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api.routes import api_router, public_router
from app.config import Settings, get_settings
from app.db import make_engine, make_session_factory
from app.security import RateLimiter


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    resolved.check()
    engine = make_engine(resolved.database_url)
    session_factory = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        app.state.engine.dispose()

    app = FastAPI(title="LoopMonitor", version=__version__, lifespan=lifespan)
    app.state.settings = resolved
    app.state.engine = engine
    app.state.SessionLocal = session_factory
    app.state.login_limiter = RateLimiter()
    app.state.probe_limiter = RateLimiter()
    app.include_router(public_router)
    app.include_router(api_router)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    return app


app = create_app()
