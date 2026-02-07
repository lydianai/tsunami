"""
TSUNAMI Async Utilities - AILYDIAN AutoFix Generated
Production-ready async helpers for concurrent operations
"""

import asyncio
import functools
import logging
from typing import Any, Callable, List, Optional, TypeVar
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

T = TypeVar('T')

# Shared thread pool for sync-to-async conversion
_executor = ThreadPoolExecutor(max_workers=10)


async def gather_with_concurrency(
    n: int,
    *coros,
    return_exceptions: bool = False
) -> List[Any]:
    """
    Run coroutines with limited concurrency.

    Usage:
        results = await gather_with_concurrency(
            5,  # Max 5 concurrent tasks
            fetch_data(url1),
            fetch_data(url2),
            fetch_data(url3),
            ...
        )

    Args:
        n: Maximum number of concurrent tasks
        *coros: Coroutines to execute
        return_exceptions: If True, exceptions are returned as results

    Returns:
        List of results in the same order as input coroutines
    """
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(
        *[sem_coro(coro) for coro in coros],
        return_exceptions=return_exceptions
    )


async def retry_async(
    coro_func: Callable[..., Any],
    *args,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    **kwargs
) -> Any:
    """
    Retry an async function with exponential backoff.

    Usage:
        result = await retry_async(
            fetch_api_data,
            url,
            max_retries=5,
            delay=0.5,
            backoff=2.0
        )

    Args:
        coro_func: Async function to retry
        *args: Positional arguments for the function
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry
        exceptions: Tuple of exceptions to catch and retry
        **kwargs: Keyword arguments for the function

    Returns:
        Result of the successful function call

    Raises:
        Last exception if all retries fail
    """
    last_exception = None
    current_delay = delay

    for attempt in range(max_retries + 1):
        try:
            return await coro_func(*args, **kwargs)
        except exceptions as e:
            last_exception = e
            if attempt < max_retries:
                logger.warning(
                    f"Retry {attempt + 1}/{max_retries} for {coro_func.__name__}: {e}"
                )
                await asyncio.sleep(current_delay)
                current_delay *= backoff
            else:
                logger.error(
                    f"All {max_retries} retries failed for {coro_func.__name__}: {e}"
                )

    raise last_exception


async def timeout_async(
    coro: Any,
    timeout: float,
    default: Any = None
) -> Any:
    """
    Run a coroutine with timeout, returning default on timeout.

    Usage:
        result = await timeout_async(slow_operation(), timeout=5.0, default=[])

    Args:
        coro: Coroutine to execute
        timeout: Timeout in seconds
        default: Value to return on timeout

    Returns:
        Result of coroutine or default value on timeout
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning(f"Operation timed out after {timeout}s")
        return default


def run_sync(func: Callable[..., T]) -> Callable[..., asyncio.Future[T]]:
    """
    Decorator to run a synchronous function in a thread pool.

    Usage:
        @run_sync
        def blocking_io_operation(data):
            # This runs in a thread pool
            return process(data)

        # Can be awaited
        result = await blocking_io_operation(data)
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor,
            functools.partial(func, *args, **kwargs)
        )
    return wrapper


class AsyncBatcher:
    """
    Batch multiple async requests into single operations.

    Usage:
        batcher = AsyncBatcher(batch_size=10, delay=0.1)

        @batcher.batch('api_calls')
        async def fetch_user(user_id):
            return await api.get_user(user_id)

        # These will be batched together
        users = await asyncio.gather(
            fetch_user(1),
            fetch_user(2),
            fetch_user(3)
        )
    """

    def __init__(self, batch_size: int = 10, delay: float = 0.05):
        self.batch_size = batch_size
        self.delay = delay
        self._pending = {}
        self._locks = {}

    def batch(self, group: str):
        """Decorator to batch async function calls"""
        if group not in self._pending:
            self._pending[group] = []
            self._locks[group] = asyncio.Lock()

        def decorator(func: Callable):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                async with self._locks[group]:
                    future = asyncio.Future()
                    self._pending[group].append((args, kwargs, future))

                    if len(self._pending[group]) >= self.batch_size:
                        await self._flush(group, func)
                    else:
                        # Schedule flush after delay
                        asyncio.create_task(self._delayed_flush(group, func))

                return await future

            return wrapper
        return decorator

    async def _delayed_flush(self, group: str, func: Callable):
        """Flush batch after delay if not already flushed"""
        await asyncio.sleep(self.delay)
        async with self._locks[group]:
            if self._pending[group]:
                await self._flush(group, func)

    async def _flush(self, group: str, func: Callable):
        """Execute all pending calls"""
        pending = self._pending[group]
        self._pending[group] = []

        for args, kwargs, future in pending:
            try:
                result = await func(*args, **kwargs)
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)


async def parallel_map(
    func: Callable,
    items: List[Any],
    concurrency: int = 5
) -> List[Any]:
    """
    Apply an async function to items in parallel with limited concurrency.

    Usage:
        async def process_item(item):
            return await api.process(item)

        results = await parallel_map(process_item, items, concurrency=10)
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_call(item):
        async with semaphore:
            return await func(item)

    return await asyncio.gather(*[bounded_call(item) for item in items])
