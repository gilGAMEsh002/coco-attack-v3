"""Single-host rate limiting and token admission (task book E §7).

The limiter is a sliding-window admission controller over a bounded set of
in-flight model requests.  It throttles both request count and tokens per unit
time and lets a caller reconcile the reserved estimate with the actual usage
once the response (or a cache hit) is known.

Only one algorithm is implemented (sliding window), as the plan permits; the
clock and sleep functions are injectable so the behaviour is deterministic in
tests.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field


def estimate_tokens(text: str) -> int:
    """Conservative input-token estimate (4 characters per token)."""

    return max(1, math.ceil(len(text) / 4))


@dataclass
class _Event:
    ts: float
    tokens: int


class RateLimitUnsatisfiable(ValueError):
    """A single request can never satisfy the configured rate limit."""


@dataclass
class _Permit:
    limiter: "SlidingWindowLimiter"
    request_event: _Event
    token_event: _Event
    estimated_tokens: int
    settled: bool = field(default=False)

    def settle(self, *, actual_tokens: int | None = None, cached: bool = False) -> None:
        """Reconcile the reservation: refund a cache hit, else set actual usage."""

        self.limiter._settle(
            self,
            actual_tokens=actual_tokens,
            cached=cached,
        )


class SlidingWindowLimiter:
    def __init__(
        self,
        *,
        requests_per_minute: float | None = None,
        tokens_per_minute: int | None = None,
        window_seconds: float = 60.0,
        clock=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        if requests_per_minute is not None and requests_per_minute < 1:
            raise ValueError("requests_per_minute must be at least 1 or None")
        if tokens_per_minute is not None and tokens_per_minute <= 0:
            raise ValueError("tokens_per_minute must be positive or None")
        self.requests_per_minute = requests_per_minute
        self.tokens_per_minute = tokens_per_minute
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._requests: deque[_Event] = deque()
        self._tokens: deque[_Event] = deque()

    # -- internals ---------------------------------------------------------- #

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._requests and self._requests[0].ts <= cutoff:
            self._requests.popleft()
        while self._tokens and self._tokens[0].ts <= cutoff:
            self._tokens.popleft()

    def _token_total(self) -> int:
        return sum(event.tokens for event in self._tokens)

    def _allowed(self, estimated_tokens: int) -> bool:
        if self.requests_per_minute is not None:
            if len(self._requests) + 1 > self.requests_per_minute:
                return False
        if self.tokens_per_minute is not None:
            if self._token_total() + estimated_tokens > self.tokens_per_minute:
                return False
        return True

    def _wait_seconds(self, now: float, estimated_tokens: int) -> float:
        waits = [0.0]
        if self.requests_per_minute is not None:
            excess = len(self._requests) + 1 - int(self.requests_per_minute)
            if excess > 0 and len(self._requests) >= excess:
                waits.append(self._requests[excess - 1].ts + self.window_seconds - now)
        if self.tokens_per_minute is not None:
            budget = self.tokens_per_minute - estimated_tokens
            running = 0
            for event in self._tokens:
                running += event.tokens
                if running > max(budget, 0):
                    waits.append(event.ts + self.window_seconds - now)
                    break
        return max(waits)

    def _settle(self, permit: _Permit, *, actual_tokens: int | None, cached: bool) -> None:
        with self._lock:
            if permit.settled:
                return
            permit.settled = True
            if cached:
                self._remove(self._requests, permit.request_event)
                self._remove(self._tokens, permit.token_event)
                return
            if actual_tokens is not None:
                permit.token_event.tokens = max(0, int(actual_tokens))

    @staticmethod
    def _remove(events: deque[_Event], target: _Event) -> None:
        for index, event in enumerate(events):
            if event is target:
                del events[index]
                return

    # -- public ------------------------------------------------------------- #

    def acquire(self, estimated_tokens: int = 0) -> _Permit:
        estimated_tokens = max(0, int(estimated_tokens))
        if self.tokens_per_minute is not None and estimated_tokens > self.tokens_per_minute:
            # The window can never satisfy a single request this large; refuse
            # instead of blocking the run forever.
            raise RateLimitUnsatisfiable(
                f"estimated {estimated_tokens} tokens exceeds tokens_per_minute="
                f"{self.tokens_per_minute}"
            )
        while True:
            with self._lock:
                now = self._clock()
                self._prune(now)
                if self._allowed(estimated_tokens):
                    request_event = _Event(ts=now, tokens=0)
                    token_event = _Event(ts=now, tokens=estimated_tokens)
                    self._requests.append(request_event)
                    self._tokens.append(token_event)
                    return _Permit(
                        limiter=self,
                        request_event=request_event,
                        token_event=token_event,
                        estimated_tokens=estimated_tokens,
                    )
                wait = self._wait_seconds(now, estimated_tokens)
            self._sleep(max(wait, 0.001))
