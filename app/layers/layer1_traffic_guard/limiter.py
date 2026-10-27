
import asyncio
import time
import uuid
from collections import defaultdict, deque

from redis.asyncio import Redis


REDIS_LIMIT_SCRIPT = """
local blocked = redis.call('EXISTS', KEYS[2])
if blocked == 1 then
    return 0
end

local now = tonumber(ARGV[1])
local window_start = now - tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local block_seconds = tonumber(ARGV[4])
local member = ARGV[5]

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', window_start)

local count = redis.call('ZCARD', KEYS[1])
if count >= max_requests then
    redis.call('SET', KEYS[2], '1', 'EX', block_seconds)
    return 0
end

redis.call('ZADD', KEYS[1], now, member)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]) + block_seconds + 5)

return 1
"""


class MemoryLimiter:
    """Single-process limiter for development and tests only."""

    def __init__(self):
        self.history = defaultdict(deque)
        self.blocked_until = {}
        self.lock = asyncio.Lock()

    async def allow(self, client_id, limit, window, block_seconds):
        now = time.monotonic()

        async with self.lock:
            if self.blocked_until.get(client_id, 0) > now:
                return False

            self.blocked_until.pop(client_id, None)
            history = self.history[client_id]
            cutoff = now - window

            while history and history[0] <= cutoff:
                history.popleft()

            if len(history) >= limit:
                self.blocked_until[client_id] = now + block_seconds
                return False

            history.append(now)
            return True

    async def close(self):
        return None


class RedisLimiter:
    """Shared atomic sliding-window limiter using Redis."""

    def __init__(self, redis_url):
        self.redis = Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )

    async def allow(self, client_id, limit, window, block_seconds):
        now_ms = int(time.time() * 1000)
        window_ms = window * 1000

        # Hash the client identifier before using it in Redis keys.
        import hashlib
        client_key = hashlib.sha256(
            client_id.encode("utf-8")
        ).hexdigest()

        allowed = await self.redis.eval(
            REDIS_LIMIT_SCRIPT,
            2,
            f"argusx:traffic:{client_key}",
            f"argusx:blocked:{client_key}",
            now_ms,
            window_ms,
            limit,
            block_seconds,
            f"{now_ms}:{uuid.uuid4().hex}",
        )

        return bool(allowed)

    async def close(self):
        await self.redis.aclose()
