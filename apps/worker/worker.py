import asyncio
import time

from nope_api.config import get_settings
from nope_api.db import run_migrations
from nope_api.queue import worker_loop
from nope_api.scanners import _bounded_redacted


def main() -> None:
    settings = get_settings()
    run_migrations(settings)
    print("NOPE worker is ready. Waiting for Redis scan jobs.")
    while True:
        try:
            asyncio.run(worker_loop(settings))
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            print(f"NOPE worker queue loop restarted after error: {_bounded_redacted(str(exc), 4096)}")
            time.sleep(5)


if __name__ == "__main__":
    main()
