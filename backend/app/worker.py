from __future__ import annotations

import asyncio
import logging

from app.config import get_settings
from app.monitoring.scheduler import serve


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    asyncio.run(serve(settings))


if __name__ == "__main__":
    main()
