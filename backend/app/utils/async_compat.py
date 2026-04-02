"""asyncio helpers for Python 3.8 (asyncio.to_thread is 3.9+)."""

from __future__ import annotations

import asyncio
import functools
import sys
from typing import Any, Callable, TypeVar

T = TypeVar("T")

if sys.version_info >= (3, 9):
    to_thread: Callable[..., Any] = asyncio.to_thread
else:

    async def to_thread(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            functools.partial(func, *args, **kwargs),
        )
