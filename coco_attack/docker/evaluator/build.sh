#!/usr/bin/env bash
# Build the CoCo-Attack evaluation image with a digest-pinned base.
#
# Usage:
#   ./build.sh <python:3.14-slim@sha256:...> <image-tag>
#
# The base digest is mandatory and is never pre-filled in the Dockerfile.  The
# resulting local image id (sha256:...) is printed so it can be recorded in the
# execution profile; a locally built image is identified by its image id, not by
# a registry RepoDigest.
#
# This script requires a working Docker daemon.  Building downloads and installs
# packages, so it needs network access at build time only; the resulting image
# runs with --network=none.

set -euo pipefail

BASE_REF="${1:-}"
IMAGE_TAG="${2:-}"

if [[ -z "${BASE_REF}" ]]; then
    echo "usage: $0 <python:3.14-slim@sha256:...> <image-tag>" >&2
    echo "error: a digest-pinned base image is required" >&2
    exit 2
fi
if [[ "${BASE_REF}" != *"@sha256:"* ]]; then
    echo "error: base image must be pinned by digest (got '${BASE_REF}')" >&2
    exit 2
fi
if [[ -z "${IMAGE_TAG}" ]]; then
    echo "usage: $0 <base-ref> <image-tag>" >&2
    exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Optional build-time package index (does not affect the pinned versions).
PIP_INDEX="${PIP_INDEX_URL:-https://pypi.org/simple}"
if [[ "${PIP_INDEX}" == *"@"* ]]; then
    echo "error: PIP_INDEX_URL must not contain credentials; use a BuildKit secret instead" >&2
    exit 2
fi

docker build \
    --file "${here}/Dockerfile" \
    --build-arg "PYTHON_BASE=${BASE_REF}" \
    --build-arg "PIP_INDEX_URL=${PIP_INDEX}" \
    --build-arg "COCO_BASE_DIGEST=${BASE_REF}" \
    --tag "${IMAGE_TAG}" \
    "${here}"

image_id="$(docker image inspect --format '{{.Id}}' "${IMAGE_TAG}")"

# Record a build manifest (plan 4.2.5): base digest, context/lock hashes, image id.
manifest="${COCO_BUILD_MANIFEST:-${here}/build_manifest.json}"
python3 - "${BASE_REF}" "${IMAGE_TAG}" "${image_id}" "${PIP_INDEX}" "${here}" "${manifest}" <<'PY'
import hashlib, json, pathlib, sys, datetime
base_ref, tag, image_id, pip_index, here, manifest = sys.argv[1:7]
here_path = pathlib.Path(here)

def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

payload = {
    "schema_version": "1",
    "base_reference": base_ref,
    "image_tag": tag,
    "image_id": image_id,
    "pip_index_url": pip_index,
    "context_files": {
        name: sha256(here_path / name)
        for name in ("Dockerfile", "requirements-eval.lock", "entrypoint.py", "probe_runner.py", "search_client.py", "functional_runner.py", "dynamic_runner.py", "realism_runner.py", "bigcodebench/eval/utils.py")
    },
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
}
pathlib.Path(manifest).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print(f"build manifest: {manifest}")
PY

echo "built ${IMAGE_TAG}"
echo "local image id: ${image_id}"
echo "record this image id as image.image_id in the execution profile (all-zero placeholder is resolved by check-execution)."
