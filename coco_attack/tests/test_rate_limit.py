"""Sliding-window rate limiting and token admission (batch-3 component 2)."""

from __future__ import annotations

import pytest

from coco_attack.generation.contracts import GenerationConfig, GenerationContractError
from coco_attack.runtime.limits import (
    RateLimitUnsatisfiable,
    SlidingWindowLimiter,
    estimate_tokens,
)


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _advanced_sleep(clock: _Clock):
    calls: list[float] = []

    def _sleep(seconds: float) -> None:
        calls.append(seconds)
        clock.t += seconds

    return _sleep, calls


def test_estimate_tokens_is_positive_and_monotonic() -> None:
    assert estimate_tokens("") == 1
    assert estimate_tokens("a" * 8) == 2
    assert estimate_tokens("a" * 100) >= estimate_tokens("a" * 10)


def test_request_limit_blocks_until_window() -> None:
    clock = _Clock()
    sleep, calls = _advanced_sleep(clock)
    limiter = SlidingWindowLimiter(requests_per_minute=2, clock=clock, sleep=sleep)
    for _ in range(2):
        permit = limiter.acquire(0)
        permit.settle(actual_tokens=0, cached=False)
    # The third request must wait for the window to slide.
    permit = limiter.acquire(0)
    assert calls, "third request should have blocked"
    assert clock.t >= 60.0
    permit.settle(actual_tokens=0, cached=False)


def test_token_limit_blocks_until_window() -> None:
    clock = _Clock()
    sleep, calls = _advanced_sleep(clock)
    limiter = SlidingWindowLimiter(tokens_per_minute=10, clock=clock, sleep=sleep)
    first = limiter.acquire(8)
    first.settle(actual_tokens=8, cached=False)
    second = limiter.acquire(5)
    assert calls, "token-bound request should have blocked"
    assert clock.t >= 60.0
    second.settle(actual_tokens=5, cached=False)


def test_cache_hit_refunds_the_reservation() -> None:
    clock = _Clock()
    sleep, calls = _advanced_sleep(clock)
    limiter = SlidingWindowLimiter(requests_per_minute=1, clock=clock, sleep=sleep)
    cached = limiter.acquire(100)
    cached.settle(cached=True)
    # No physical request happened, so the next acquire must not block.
    fresh = limiter.acquire(100)
    fresh.settle(actual_tokens=1, cached=False)
    assert calls == []


def test_settle_replaces_estimate_with_actual() -> None:
    limiter = SlidingWindowLimiter(tokens_per_minute=100)
    permit = limiter.acquire(90)
    assert limiter._token_total() == 90
    permit.settle(actual_tokens=3, cached=False)
    assert limiter._token_total() == 3


def test_unsatisfiable_single_request_is_refused_not_blocked() -> None:
    clock = _Clock()
    sleep, calls = _advanced_sleep(clock)
    limiter = SlidingWindowLimiter(tokens_per_minute=100, clock=clock, sleep=sleep)
    with pytest.raises(RateLimitUnsatisfiable):
        limiter.acquire(101)
    assert calls == [], "must refuse immediately, not wait"

    with pytest.raises(ValueError):
        SlidingWindowLimiter(requests_per_minute=0.5)


def test_config_rejects_non_positive_limits() -> None:
    base = dict(
        source="mock", model="m", batch_id="b", combination_id="cwe078-0",
        oracle_id="cwe078-0", stage="search", form="clean_fewshot_cot",
        prompt_version="1", candidate_hash="", temperature=0.0, repeats=1,
        max_tokens=8, request_timeout=1.0, max_concurrency=1,
        max_request_attempts=1, max_sample_retries=0,
    )
    with pytest.raises(GenerationContractError):
        GenerationConfig(**base, requests_per_minute=0)
    with pytest.raises(GenerationContractError):
        GenerationConfig(**base, tokens_per_minute=-5)
    config = GenerationConfig(**base, requests_per_minute=10, tokens_per_minute=100)
    assert config.to_json()["requests_per_minute"] == 10
    assert config.to_json()["tokens_per_minute"] == 100
