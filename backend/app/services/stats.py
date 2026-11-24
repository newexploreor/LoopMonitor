from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CheckResult

WINDOWS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def window_delta(name: str) -> timedelta:
    try:
        return WINDOWS[name]
    except KeyError as exc:
        raise ValueError("统计窗口只支持 24h、7d、30d") from exc


def _p95(values: list[int]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return float(ordered[index])


def _ratio(success: int, total: int) -> float | None:
    if total <= 0:
        return None
    return round(success * 100 / total, 2)


def _average(values: list[int]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 2)


def load_auto_checks(
    session: Session,
    *,
    monitor_ids: list[str] | None,
    start: datetime,
    end: datetime,
) -> list[CheckResult]:
    stmt = select(CheckResult).where(
        CheckResult.trigger_type == "auto",
        CheckResult.valid.is_(True),
        CheckResult.started_at >= start,
        CheckResult.started_at < end,
    )
    if monitor_ids is not None:
        if not monitor_ids:
            return []
        stmt = stmt.where(CheckResult.monitor_id.in_(monitor_ids))
    return list(session.scalars(stmt))


def summarize_checks(rows: list[CheckResult]) -> dict:
    successes = [row for row in rows if row.success]
    latencies = [row.latency_ms for row in successes if row.latency_ms is not None]
    return {
        "total": len(rows),
        "success": len(successes),
        "availability": _ratio(len(successes), len(rows)),
        "avg_latency_ms": _average(latencies),
        "p95_latency_ms": _p95(latencies),
    }


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def bucket_trend(rows: list[CheckResult], start: datetime, end: datetime, window: str) -> list[dict]:
    step = timedelta(hours=1) if window in {"24h", "7d"} else timedelta(days=1)
    buckets: list[dict] = []
    cursor = _aware(start)
    end = _aware(end)
    while cursor < end:
        nxt = min(end, cursor + step)
        chunk = [row for row in rows if cursor <= _aware(row.started_at) < nxt]
        summary = summarize_checks(chunk)
        buckets.append(
            {
                "start": cursor.isoformat(),
                "end": nxt.isoformat(),
                "total": summary["total"],
                "availability": summary["availability"],
                "avg_latency_ms": summary["avg_latency_ms"],
            }
        )
        cursor = nxt
    return buckets


def per_monitor(rows: list[CheckResult]) -> dict[str, dict]:
    grouped: dict[str, list[CheckResult]] = {}
    for row in rows:
        grouped.setdefault(row.monitor_id, []).append(row)
    return {monitor_id: summarize_checks(items) for monitor_id, items in grouped.items()}


def recent_statuses(session: Session, monitor_ids: list[str], limit: int = 20) -> dict[str, list[dict]]:
    if not monitor_ids:
        return {}
    rows = session.scalars(
        select(CheckResult)
        .where(CheckResult.monitor_id.in_(monitor_ids), CheckResult.trigger_type == "auto")
        .order_by(CheckResult.started_at.desc())
    ).all()
    grouped: dict[str, list[dict]] = {monitor_id: [] for monitor_id in monitor_ids}
    for row in rows:
        bucket = grouped[row.monitor_id]
        if len(bucket) >= limit:
            continue
        bucket.append({"success": row.success, "valid": row.valid, "started_at": row.started_at.isoformat()})
    for items in grouped.values():
        items.reverse()
    return grouped
