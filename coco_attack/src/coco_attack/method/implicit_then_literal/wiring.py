"""Explicit run wiring for ``implicit_then_literal`` (subplan 04-a).

This module owns the *configuration -> services* boundary for the method:

* one explicit run-config JSON (a superset of the flat ``MethodRuntimeConfig``
  fields) with a deterministic identity and JSON round-trip;
* relative paths are resolved once against an explicit project/repo root at load
  time, and the content identity of every referenced read-only input is recorded
  so editing a file in place is refused on the same run root;
* explicit, serializable victim source/params and proposer/inducer role sources;
* a **lazy** DMX role-source proxy that does not load a credential or construct a
  ``dspy.LM`` until the first ``generate`` call;
* a lazy victim runner that builds on the public training loop and delegates the
  real generation first/resume step to the existing subprocess path (no request
  retry/cache reimplementation);
* :func:`assemble_services`, which returns a :class:`RuntimeServices` for the
  offline double mode or the real (lazy DMX + real adapters) mode.

Importing this module never loads a credential, constructs an LM, touches the
network or runs a tool.  Production wiring never silently falls back to mock.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ...assets.artifacts import (
    canonical_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)
from ...iteration.action_runtime import (
    RoleCallConfig,
    RoleCallSource,
)
from ...iteration.code_check import ExampleCheckRequest
from ...iteration.training_loop import TrainingLoopConfig, run_training_loop
from .runtime import (
    MethodRuntimeConfig,
    RuntimeServices,
    default_gate_runner,
)

WIRING_SCHEMA_VERSION = "itl-method-wiring-v1"

#: DMX routes OpenAI-compatible model names behind a provider prefix.  The
#: mapping is recorded separately from the research model name: the prefix is a
#: routing detail, never a licence to substitute a different model.
DMX_PROVIDER_PREFIX = "openai/"
PROVIDER_MODEL_MAP: Mapping[str, str] = {
    "deepseek-v4-flash": "openai/deepseek-v4-flash",
    "DeepSeek-V3.2": "openai/DeepSeek-V3.2",
}

#: Method config fields that are filesystem paths and are resolved against the
#: explicit project root at load time.
_PATH_FIELDS = (
    "run_root",
    "repository_root",
    "assets_root",
    "prepared_data_dir",
    "initial_template_path",
    "comparison_baseline_path",
    "execution_config_path",
    "semgrep_config",
)

#: ``(binding key, method field)`` pairs whose content identity is recorded so a
#: mid-run edit is detected instead of being treated as the same run.
_BINDING_FIELDS = (
    ("initial_template", "initial_template_path"),
    ("comparison_baseline", "comparison_baseline_path"),
    ("execution_config", "execution_config_path"),
    ("semgrep_config", "semgrep_config"),
)


class WiringError(ValueError):
    """Raised when the run wiring/config is inconsistent or unsafe."""


def effective_model_name(research_model: str) -> str:
    """Map a research model name to the SDK-effective call name.

    Unknown names get the standard DMX provider prefix rather than being silently
    accepted unchanged; the research name remains the config identity.
    """

    if not isinstance(research_model, str) or not research_model:
        raise WiringError("model name must be a non-empty string")
    mapped = PROVIDER_MODEL_MAP.get(research_model)
    if mapped is not None:
        return mapped
    return f"{DMX_PROVIDER_PREFIX}{research_model}"


# --------------------------------------------------------------------------- #
# Run config load / identity
# --------------------------------------------------------------------------- #


def _resolve_root(project_root: str | Path) -> Path:
    if project_root is None or str(project_root) == "":
        raise WiringError("an explicit project/repo root is required")
    root = Path(project_root).expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    return root.resolve()


def _resolve_path_field(value: str, root: Path) -> str:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    return str(candidate.resolve())


def _tree_identity(path: Path) -> str:
    entries: list[list[str]] = []
    for child in sorted(path.rglob("*")):
        if child.is_file():
            entries.append([child.relative_to(path).as_posix(), sha256_file(child)])
    return sha256_bytes(canonical_json_bytes(entries))


def content_identity(path: str | Path | None) -> str:
    """Deterministic content identity of a referenced read-only input.

    A missing path is reported as ``"missing"`` (never silently equal to an
    empty file).  A directory is identified by the hash of its file tree; a
    snapshot directory is identified by its ``snapshot.json``.
    """

    if path is None:
        return "missing"
    candidate = Path(path).expanduser()
    if candidate.is_dir():
        snapshot = candidate / "snapshot.json"
        if snapshot.is_file():
            return sha256_file(snapshot)
        return _tree_identity(candidate)
    if candidate.is_file():
        return sha256_file(candidate)
    return "missing"


@dataclass(frozen=True)
class MethodRunConfig:
    """A loaded, path-resolved method run configuration.

    ``method`` is a fully resolved :class:`MethodRuntimeConfig` (absolute
    paths, computed ``input_binding``).  ``project_root`` is retained only so the
    same file can be re-resolved and so the provenance of the resolution is
    visible; the run identity is the method config identity, which already
    includes every research-relevant field and the referenced content hashes.
    """

    project_root: str
    method: MethodRuntimeConfig

    def __post_init__(self) -> None:
        if not isinstance(self.project_root, str) or not self.project_root:
            raise WiringError("config.project_root must be a non-empty string")
        if not isinstance(self.method, MethodRuntimeConfig):
            raise WiringError("config.method must be a MethodRuntimeConfig")

    @property
    def run_root(self) -> Path:
        return Path(self.method.run_root)

    def config_sha256(self) -> str:
        return self.method.config_sha256()

    def source_summary(self) -> dict[str, Any]:
        return {
            "proposer": self.method.proposer_config.source,
            "inducer": self.method.inducer_config.source,
            "victim": self.method.victim_source,
            "check_service": self.method.check_service,
            "effective_models": {
                "proposer": effective_model_name(self.method.proposer_config.model),
                "inducer": effective_model_name(self.method.inducer_config.model),
                "victim": effective_model_name(self.method.victim_model),
            },
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": WIRING_SCHEMA_VERSION,
            "project_root": self.project_root,
            **self.method.to_json(),
        }

    @classmethod
    def from_json(
        cls,
        payload: Mapping[str, Any],
        *,
        project_root: str | Path | None = None,
    ) -> "MethodRunConfig":
        if not isinstance(payload, Mapping):
            raise WiringError("method run config must be a JSON object")
        data = dict(payload)
        data.pop("schema_version", None)
        root_value = project_root if project_root is not None else data.pop("project_root", None)
        if root_value is None:
            raise WiringError("method run config is missing an explicit project_root")
        root = _resolve_root(root_value)

        for name in _PATH_FIELDS:
            value = data.get(name)
            if value is None:
                continue
            if not isinstance(value, str) or not value:
                raise WiringError(f"config.{name} must be a non-empty string or null")
            data[name] = _resolve_path_field(value, root)

        # The content identity is recomputed at load time: the persisted value is
        # never trusted over the actual referenced bytes.
        binding: list[tuple[str, str]] = []
        for key, field_name in _BINDING_FIELDS:
            value = data.get(field_name)
            if value is None:
                continue
            binding.append((key, content_identity(value)))
        data["input_binding"] = tuple(sorted(binding))

        method = MethodRuntimeConfig.from_json(data)
        return cls(project_root=str(root), method=method)


def load_method_run_config(
    path: str | Path,
    *,
    project_root: str | Path | None = None,
) -> MethodRunConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise WiringError(f"method run config is not a file: {config_path}")
    payload = read_json(config_path)
    return MethodRunConfig.from_json(payload, project_root=project_root)


# --------------------------------------------------------------------------- #
# Lazy DMX role source
# --------------------------------------------------------------------------- #


def build_dspy_role_source(config: RoleCallConfig, api_key: str) -> RoleCallSource:
    """Default provider builder: a real ``DspyRoleSource`` (imports dspy lazily)."""

    from ...iteration.action_runtime import DspyRoleSource

    return DspyRoleSource(config, api_key)


def make_credential_loader(repo_dir: str | Path | None) -> Callable[[], str]:
    """Return a zero-arg credential loader bound to the explicit repo dir."""

    def load() -> str:
        from ...generation.service import load_dmx_api_key

        return load_dmx_api_key(repo_dir)

    return load


class LazyDmxRoleSource:
    """Defer credential load + LM construction to the first ``generate`` call.

    ``run_role_call`` short-circuits on an already-durable response without
    calling ``generate``; a saved-response resume, an already-completed run and
    read-only/status paths therefore never build the provider.  The counters make
    that property directly assertable in tests.
    """

    kind = "dmx"

    def __init__(
        self,
        config: RoleCallConfig,
        *,
        credential_loader: Callable[[], str],
        provider_builder: Callable[[RoleCallConfig, str], RoleCallSource],
    ) -> None:
        if config.source != "dmx":
            raise WiringError("LazyDmxRoleSource requires a config with source='dmx'")
        self.research_config = config
        self._credential_loader = credential_loader
        self._provider_builder = provider_builder
        self._inner: RoleCallSource | None = None
        self.build_count = 0
        self.credential_load_count = 0

    @property
    def effective_config(self) -> RoleCallConfig:
        return replace(self.research_config, model=effective_model_name(self.research_config.model))

    def generate(
        self,
        messages: list[dict[str, str]],
        *,
        rollout_id: int,
        attempt_index: int,
    ):
        if self._inner is None:
            api_key = self._credential_loader()
            self.credential_load_count += 1
            self._inner = self._provider_builder(self.effective_config, api_key)
            self.build_count += 1
        return self._inner.generate(
            messages, rollout_id=rollout_id, attempt_index=attempt_index
        )


# --------------------------------------------------------------------------- #
# Lazy victim runner
# --------------------------------------------------------------------------- #


def make_victim_runner(
    config: MethodRuntimeConfig,
    *,
    generation_step: Callable[..., int] | None = None,
    generation_resume_step: Callable[..., int] | None = None,
    training_loop: Callable[..., Mapping[str, Any]] | None = None,
) -> Callable[[TrainingLoopConfig], Mapping[str, Any]]:
    """Build the victim training runner for the configured explicit source.

    The runtime builds the :class:`TrainingLoopConfig` (with the configured
    ``source``/model/params); this runner only forwards the two public generation
    boundary hooks into ``run_training_loop``.  For a real victim it leaves them
    ``None`` so the existing subprocess first/resume path (and its request
    retry/cache) is reused unchanged.  It refuses a training config whose source
    does not match the configured victim source, so a caller can never silently
    fall back to mock.
    """

    loop = training_loop or run_training_loop
    expected_source = config.victim_source

    def runner(training_config: TrainingLoopConfig) -> Mapping[str, Any]:
        if not isinstance(training_config, TrainingLoopConfig):
            raise WiringError("victim runner requires a TrainingLoopConfig")
        if training_config.source != expected_source:
            raise WiringError(
                "victim runner refused a training config with source="
                f"{training_config.source!r}; expected {expected_source!r} "
                "(no hardcoded mock fallback)"
            )
        effective = training_config
        if expected_source == "dmx":
            # The research model name is kept in the method config identity; the
            # SDK-effective provider-prefixed name is applied at the generation
            # boundary so first generation and resume both use it.
            effective = replace(
                training_config,
                model=effective_model_name(training_config.model),
            )
        return loop(
            effective,
            generation_step=generation_step,
            generation_resume_step=generation_resume_step,
        )

    return runner


# --------------------------------------------------------------------------- #
# Service assembly
# --------------------------------------------------------------------------- #


@dataclass
class WiringDoubles:
    """Explicit offline doubles / boundary spies for :func:`assemble_services`.

    In mock mode the role sources, the example-check gate and the credential /
    provider factory must all be supplied explicitly; the assembly never
    fabricates a mock fallback for a real source.  In real mode every field is an
    optional override used by the (explicitly marked) offline wiring tests.
    """

    proposer_source: RoleCallSource | None = None
    inducer_source: RoleCallSource | None = None
    gate_runner: Callable[[ExampleCheckRequest], Mapping[str, Any]] | None = None
    training_runner: Callable[[TrainingLoopConfig], Mapping[str, Any]] | None = None
    materials_builder: Callable[..., Any] | None = None
    baseline_loader: Callable[..., Any] | None = None
    credential_loader: Callable[[], str] | None = None
    provider_builder: Callable[[RoleCallConfig, str], RoleCallSource] | None = None
    generation_step: Callable[..., int] | None = None
    generation_resume_step: Callable[..., int] | None = None
    training_loop: Callable[..., Mapping[str, Any]] | None = None
    allow_mixed_sources: bool = False
    on_event: Callable[[str], None] | None = None


def _normalised_service_set(method: MethodRuntimeConfig) -> set[str]:
    services = {
        method.proposer_config.source,
        method.inducer_config.source,
        method.victim_source,
    }
    services.add("dmx" if method.check_service == "real" else "mock")
    return services


def _resolve_role_source(
    role: str,
    config: RoleCallConfig,
    *,
    method: MethodRuntimeConfig,
    provided: RoleCallSource | None,
    doubles: WiringDoubles,
) -> RoleCallSource:
    if provided is not None:
        return provided
    if config.source == "mock":
        raise WiringError(
            f"{role} source is 'mock'; pass an explicit offline double via "
            "WiringDoubles rather than relying on an implicit fallback"
        )
    credential_loader = doubles.credential_loader or make_credential_loader(
        method.repository_root
    )
    provider_builder = doubles.provider_builder or build_dspy_role_source
    return LazyDmxRoleSource(
        config,
        credential_loader=credential_loader,
        provider_builder=provider_builder,
    )


def assemble_services(
    config: MethodRunConfig,
    *,
    doubles: WiringDoubles | None = None,
) -> RuntimeServices:
    """Assemble the injectable external actions for one loaded run config.

    Mock mode (all services mock) requires explicit offline doubles and never
    touches the real gate/scanner.  Real mode builds lazy DMX role sources and
    the real adapters; a supplied double only overrides a boundary for an
    explicitly marked wiring test.  A mixed service selection is refused unless
    ``doubles.allow_mixed_sources`` is set.
    """

    if not isinstance(config, MethodRunConfig):
        raise WiringError("assemble_services requires a MethodRunConfig")
    doubles = doubles or WiringDoubles()
    method = config.method

    service_set = _normalised_service_set(method)
    if len(service_set) > 1 and not doubles.allow_mixed_sources:
        raise WiringError(
            f"mixed sources {sorted(service_set)} require doubles.allow_mixed_sources=True; "
            "mixed-source wiring is only valid for explicitly marked offline tests"
        )
    real_mode = "dmx" in service_set
    provided_doubles = any(
        value is not None
        for value in (
            doubles.proposer_source,
            doubles.inducer_source,
            doubles.gate_runner,
            doubles.training_runner,
            doubles.materials_builder,
            doubles.baseline_loader,
            doubles.credential_loader,
            doubles.provider_builder,
            doubles.generation_step,
            doubles.generation_resume_step,
            doubles.training_loop,
        )
    )
    if real_mode and provided_doubles and not doubles.allow_mixed_sources:
        raise WiringError(
            "a real (dmx) config refuses injected offline doubles unless "
            "WiringDoubles.allow_mixed_sources=True; refusing to mix mock results "
            "into a real run"
        )

    proposer_source = _resolve_role_source(
        "proposer",
        method.proposer_config,
        method=method,
        provided=doubles.proposer_source,
        doubles=doubles,
    )
    inducer_source = _resolve_role_source(
        "inducer",
        method.inducer_config,
        method=method,
        provided=doubles.inducer_source,
        doubles=doubles,
    )

    if doubles.gate_runner is not None:
        gate_runner = doubles.gate_runner
    elif method.check_service == "real":
        gate_runner = default_gate_runner
    else:
        raise WiringError(
            "check_service='mock' requires an explicit offline gate runner double; "
            "the real Docker/Semgrep gate is never used implicitly"
        )

    if doubles.training_runner is not None:
        training_runner = doubles.training_runner
    else:
        training_runner = make_victim_runner(
            method,
            generation_step=doubles.generation_step,
            generation_resume_step=doubles.generation_resume_step,
            training_loop=doubles.training_loop,
        )
        if not real_mode and doubles.training_loop is None:
            # A mock victim must not reach the real training adapter implicitly.
            raise WiringError(
                "mock victim mode requires an explicit offline training runner "
                "double (or a training_loop double)"
            )

    return RuntimeServices(
        proposer_source=proposer_source,
        inducer_source=inducer_source,
        gate_runner=gate_runner,
        training_runner=training_runner,
        materials_builder=doubles.materials_builder,
        baseline_loader=doubles.baseline_loader,
        on_event=doubles.on_event,
    )


__all__ = [
    "WIRING_SCHEMA_VERSION",
    "DMX_PROVIDER_PREFIX",
    "PROVIDER_MODEL_MAP",
    "WiringError",
    "effective_model_name",
    "content_identity",
    "MethodRunConfig",
    "load_method_run_config",
    "build_dspy_role_source",
    "make_credential_loader",
    "LazyDmxRoleSource",
    "make_victim_runner",
    "WiringDoubles",
    "assemble_services",
]
