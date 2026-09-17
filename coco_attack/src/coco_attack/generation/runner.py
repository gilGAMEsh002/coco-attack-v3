"""Bounded generation scheduling, retry and sample-level recovery.

The runner is deliberately small: a bounded thread pool, one Tenacity retry
loop per sample, and the ledger as the audit source of truth.  ``generations.jsonl``
is a rebuildable projection of ``sample_finalized`` ledger events.
"""

from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from tenacity import Retrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from ..assets.artifacts import canonical_json_bytes, sha256_bytes
from ..runtime.ledger import (
    EVENT_ATTEMPT_FAILED,
    EVENT_ATTEMPT_STARTED,
    EVENT_RESPONSE_RECEIVED,
    EVENT_SAMPLE_FINALIZED,
    Ledger,
)
from .contracts import (
    GenerationConfig,
    GenerationContractError,
    GenerationRecord,
    STATUS_EMPTY,
    STATUS_ERROR,
    STATUS_INVALID_RESPONSE,
    STATUS_SUCCESS,
    STATUS_TRUNCATED,
)
from .inputs import GenerationInputs, GenerationSample
from .source import ExtractedResponse, ResponseContractError, is_retryable
from ..runtime.limits import RateLimitUnsatisfiable, SlidingWindowLimiter, estimate_tokens


def _dspy_fingerprint() -> str:
    try:
        import dspy

        return f"dspy-{getattr(dspy, '__version__', 'unknown')}"
    except Exception:  # noqa: BLE001 - fingerprint is informational
        return "dspy-unknown"


def _estimate_cost(config: GenerationConfig, usage: dict[str, int]) -> dict[str, Any]:
    if not usage:
        return {"basis": "unknown", "amount": None, "currency": config.currency}
    if config.price_input_per_1k is None or config.price_output_per_1k is None:
        return {"basis": "unknown", "amount": None, "currency": config.currency}
    prompt_tokens = int(usage.get("prompt_tokens", 0))
    completion_tokens = int(usage.get("completion_tokens", 0))
    amount = (
        prompt_tokens / 1000.0 * config.price_input_per_1k
        + completion_tokens / 1000.0 * config.price_output_per_1k
    )
    return {
        "basis": "estimated",
        "amount": amount,
        "currency": config.currency,
        "pricing_version": config.pricing_version,
    }


class GenerationRunner:
    def __init__(
        self,
        config: GenerationConfig,
        inputs: GenerationInputs,
        ledger: Ledger,
        source: Any,
        run_dir: Path | str,
    ) -> None:
        self.config = config
        self.inputs = inputs
        self.ledger = ledger
        self.source = source
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.generations_path = self.run_dir / "generations.jsonl"
        self.limiter = SlidingWindowLimiter(
            requests_per_minute=config.requests_per_minute,
            tokens_per_minute=config.tokens_per_minute,
        )
        self._projection_lock = threading.Lock()
        replay = ledger.replay()
        self.finalized: dict[str, dict[str, Any]] = replay.finalized_records()
        self.first_usage: dict[str, dict[str, Any]] = replay.first_usage_by_sample()
        self.responses: dict[str, tuple[dict[str, Any], str | None]] = (
            replay.responses_by_sample()
        )
        self.incomplete_tail_path = replay.incomplete_tail_path

    # -- public ------------------------------------------------------------ #

    def run(self) -> dict[str, Any]:
        self._recover_unfinalized_responses()
        self._rebuild_projection()
        pending = [
            sample
            for sample in self.inputs.samples
            if sample.sample_id not in self.finalized
        ]
        records: list[GenerationRecord] = []
        if pending:
            self._assert_limits_satisfiable(pending)
            with ThreadPoolExecutor(max_workers=self.config.max_concurrency) as pool:
                futures = {pool.submit(self._run_sample, sample): sample for sample in pending}
                for future in as_completed(futures):
                    try:
                        records.append(future.result())
                    except Exception as error:  # noqa: BLE001 - recorded as a sample failure
                        sample = futures[future]
                        records.append(
                            self._finalize_failure(sample, f"runner_error:{type(error).__name__}: {error}")
                        )
        status_counts: dict[str, int] = {}
        for record in self.finalized.values():
            status = str(record.get("status"))
            status_counts[status] = status_counts.get(status, 0) + 1
        return {
            "requested": len(self.inputs.samples),
            "skipped_finalized": len(self.inputs.samples) - len(pending),
            "generated": len(records),
            "finalized_total": len(self.finalized),
            "status_counts": dict(sorted(status_counts.items())),
        }

    # -- per-sample -------------------------------------------------------- #

    def _assert_limits_satisfiable(self, samples: list[GenerationSample]) -> None:
        """Refuse a run whose largest request can never satisfy the token limit."""

        if self.limiter.tokens_per_minute is None:
            return
        worst = max(estimate_tokens(sample.prompt) for sample in samples) + self.config.max_tokens
        if worst > self.limiter.tokens_per_minute:
            raise RateLimitUnsatisfiable(
                f"largest request estimate {worst} tokens exceeds tokens_per_minute="
                f"{self.limiter.tokens_per_minute}; raise the limit or reduce max_tokens"
            )

    def _run_sample(self, sample: GenerationSample) -> GenerationRecord:
        retryer = Retrying(
            stop=stop_after_attempt(self.config.max_request_attempts),
            wait=wait_exponential_jitter(initial=0.01, max=0.5),
            retry=retry_if_exception(is_retryable),
            reraise=True,
        )
        try:
            for attempt in retryer:
                with attempt:
                    attempt_index = attempt.retry_state.attempt_number - 1
                    return self._attempt(sample, attempt_index)
        except ResponseContractError as error:
            return self._finalize_failure(
                sample, f"invalid_response:{error}", status=STATUS_INVALID_RESPONSE
            )
        except Exception as error:  # noqa: BLE001 - terminal sample failure
            return self._finalize_failure(sample, f"{type(error).__name__}: {error}")
        raise AssertionError("retry loop exited without result")  # pragma: no cover

    def _attempt(self, sample: GenerationSample, attempt_index: int) -> GenerationRecord:
        estimated_tokens = estimate_tokens(sample.prompt) + self.config.max_tokens
        permit = self.limiter.acquire(estimated_tokens)
        request_attempt_id = uuid.uuid4().hex
        identity = sample.identity
        self.ledger.append(
            EVENT_ATTEMPT_STARTED,
            sample_id=sample.sample_id,
            request_attempt_id=request_attempt_id,
            payload={
                "attempt_index": attempt_index,
                "model": self.config.model,
                "source": self.config.source,
                "adapter_version": self.config.__class__.__name__,
            },
        )
        try:
            extracted = self.source.generate(
                [{"role": "user", "content": sample.prompt}],
                sample.rollout_id,
                attempt_index,
            )
        except Exception as error:
            # Keep the reservation: a failed attempt may still have consumed
            # server-side time; unknown usage must not be treated as zero.
            permit.settle(actual_tokens=estimated_tokens, cached=False)
            self.ledger.append(
                EVENT_ATTEMPT_FAILED,
                sample_id=sample.sample_id,
                request_attempt_id=request_attempt_id,
                payload={
                    "attempt_index": attempt_index,
                    "error_type": type(error).__name__,
                    "error_reason": str(error),
                    "retryable": is_retryable(error),
                },
            )
            raise

        usage_dict = extracted.usage or {}
        actual_tokens = usage_dict.get("total_tokens")
        if not actual_tokens:
            actual_tokens = (usage_dict.get("prompt_tokens") or 0) + (
                usage_dict.get("completion_tokens") or 0
            )
        permit.settle(
            actual_tokens=actual_tokens or None,
            cached=extracted.cache_hit,
        )
        usage = dict(extracted.usage)
        cost = _estimate_cost(self.config, usage)
        if extracted.cache_hit and not usage:
            prior = self.first_usage.get(sample.sample_id)
            if prior:
                usage = dict(prior.get("usage") or {})
                cost = dict(prior.get("cost") or cost)
                cost["reused_from_first_response"] = True
        self.ledger.append(
            EVENT_RESPONSE_RECEIVED,
            sample_id=sample.sample_id,
            request_attempt_id=request_attempt_id,
            payload={
                "attempt_index": attempt_index,
                "content": extracted.content,
                "content_sha256": sha256_bytes(extracted.content.encode("utf-8")),
                "finish_reason": extracted.finish_reason,
                "usage": usage,
                "cost": cost,
                "cache_hit": extracted.cache_hit,
                "response_id": extracted.response_id,
                "model": extracted.model,
                "estimated_tokens": permit.estimated_tokens,
            },
        )
        status = self._status_for(extracted)
        record = self._build_record(
            sample,
            status=status,
            generation=extracted.content,
            error_reason=None,
            response_id=extracted.response_id,
            finish_reason=extracted.finish_reason,
            request_attempt_id=request_attempt_id,
            retry_count=attempt_index,
            usage=usage,
            cost=cost,
            cache_hit=extracted.cache_hit,
        )
        self._finalize(record)
        return record

    @staticmethod
    def _status_for(extracted: ExtractedResponse) -> str:
        return GenerationRunner._status_for_response(extracted.finish_reason, extracted.content)

    @staticmethod
    def _status_for_response(finish_reason: str | None, content: str) -> str:
        if finish_reason == "length":
            return STATUS_TRUNCATED
        if content == "":
            return STATUS_EMPTY
        return STATUS_SUCCESS

    def _build_record(
        self,
        sample: GenerationSample,
        *,
        status: str,
        generation: str,
        error_reason: str | None,
        response_id: str | None,
        finish_reason: str | None,
        request_attempt_id: str | None,
        retry_count: int,
        usage: dict[str, Any],
        cost: dict[str, Any],
        cache_hit: bool,
    ) -> GenerationRecord:
        identity = sample.identity
        return GenerationRecord(
            identity=identity,
            sample_id=sample.sample_id,
            rollout_id=sample.rollout_id,
            combination_id=identity.combination_id,
            oracle_id=self.inputs.oracle_id,
            source=self.config.source,
            model=self.config.model,
            form=self.inputs.form,
            run_config_hash=self.config.run_config_hash(),
            task_snapshot_sha256=self.inputs.task_snapshot_sha256,
            prompt_sha256=sample.prompt_sha256,
            status=status,
            generation=generation,
            error_reason=error_reason,
            response_id=response_id,
            finish_reason=finish_reason,
            request_attempt_id=request_attempt_id,
            retry_count=retry_count,
            usage=usage,
            cost=cost,
            cache_hit=cache_hit,
            dspy_fingerprint=_dspy_fingerprint(),
        )

    def _finalize_failure(
        self,
        sample: GenerationSample,
        reason: str,
        *,
        status: str = STATUS_ERROR,
    ) -> GenerationRecord:
        record = self._build_record(
            sample,
            status=status,
            generation="",
            error_reason=reason,
            response_id=None,
            finish_reason=None,
            request_attempt_id=None,
            retry_count=self.config.max_request_attempts - 1,
            usage={},
            cost={"basis": "unknown", "amount": None, "currency": self.config.currency},
            cache_hit=False,
        )
        self._finalize(record)
        return record

    # -- persistence ------------------------------------------------------- #

    def _recover_unfinalized_responses(self) -> None:
        """Finalize durable responses left without a ``sample_finalized`` event.

        A crash can interrupt the run between ``response_received`` and
        ``sample_finalized``.  The response bytes, usage and cost are already
        durable, so the record is rebuilt locally instead of re-issuing the
        request (which would spend again or miss the cache).
        """

        by_sample = {sample.sample_id: sample for sample in self.inputs.samples}
        for sample_id, (payload, request_attempt_id) in self.responses.items():
            if sample_id in self.finalized:
                continue
            sample = by_sample.get(sample_id)
            if sample is None:
                # A response without a matching input cannot be attributed to
                # this run; leave it in the ledger rather than guessing.
                continue
            content = payload.get("content") or ""
            record = self._build_record(
                sample,
                status=self._status_for_response(payload.get("finish_reason"), content),
                generation=content,
                error_reason=None,
                response_id=payload.get("response_id"),
                finish_reason=payload.get("finish_reason"),
                request_attempt_id=request_attempt_id,
                retry_count=int(payload.get("attempt_index") or 0),
                usage=dict(payload.get("usage") or {}),
                cost=dict(
                    payload.get("cost")
                    or {"basis": "unknown", "amount": None, "currency": self.config.currency}
                ),
                cache_hit=bool(payload.get("cache_hit")),
            )
            self._finalize(record)

    def _finalize(self, record: GenerationRecord) -> None:
        self.ledger.append(
            EVENT_SAMPLE_FINALIZED,
            sample_id=record.sample_id,
            payload={"record": record.to_json()},
        )
        self.finalized[record.sample_id] = record.to_json()
        self._append_projection(record.to_json())

    def _append_projection(self, record: dict[str, Any]) -> None:
        with self._projection_lock:
            with open(self.generations_path, "ab") as handle:
                if self._projection_needs_separator():
                    handle.write(b"\n")
                handle.write(canonical_json_bytes(record) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())

    def _projection_needs_separator(self) -> bool:
        """True when the projection ends with a record lacking its newline.

        A crash can leave a fully flushed record whose trailing newline never
        reached disk.  Appending directly would concatenate the next record onto
        it, losing both.  A leading newline keeps them separate.
        """

        if not self.generations_path.is_file():
            return False
        with open(self.generations_path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                return False
            handle.seek(-1, os.SEEK_END)
            return handle.read(1) != b"\n"

    def _rebuild_projection(self) -> None:
        """Re-append finalized ledger records missing from the projection file."""

        existing: set[str] = set()
        if self.generations_path.is_file():
            for raw in self.generations_path.read_bytes().split(b"\n"):
                if not raw.strip():
                    continue
                import json

                try:
                    row = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    continue
                if isinstance(row, dict) and row.get("sample_id"):
                    existing.add(str(row["sample_id"]))
        for sample_id, record in sorted(self.finalized.items()):
            if sample_id not in existing:
                self._append_projection(record)


__all__ = ["GenerationRunner"]
