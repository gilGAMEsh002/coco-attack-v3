# CoCo-Attack evaluation image (phase 02, task 01).
#
# This image runs a single evaluation sample (or one isolation probe) inside a
# locked-down container.  It intentionally does NOT contain DSPy, model
# credentials, the repository, the .env file or the Docker socket.
#
# Build (base must be pinned by digest at the call site; never pre-fill a digest):
#   ./build.sh python:3.14-slim@sha256:<actual-digest> coco-attack-evaluator:0.1.0
#
# The base image is supplied through ARG so that the digest lives in the build
# invocation and the build log rather than being guessed in this file.

ARG PYTHON_BASE

FROM ${PYTHON_BASE}

# Build-time only: select a package index reachable from the build host. The
# lock file still pins exact versions; this only controls where they are fetched.
ARG PIP_INDEX_URL="https://pypi.org/simple"

# Record the digest-pinned base reference in the image itself so preflight can
# verify provenance instead of trusting a profile placeholder.
ARG COCO_BASE_DIGEST=""
LABEL org.coco.base-digest="${COCO_BASE_DIGEST}"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    MPLCONFIGDIR=/tmp/matplotlib \
    PYTHONPATH=/opt/coco

# Fixed non-root identity for every sample execution.
RUN groupadd --gid 10001 coco \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin coco \
    && mkdir -p /in /out /work /opt/coco \
    && chown -R coco:coco /opt/coco /in /out /work

COPY requirements-eval.lock /opt/coco/requirements-eval.lock
RUN python -m pip install --no-cache-dir --require-hashes \
    --index-url "${PIP_INDEX_URL}" \
    --requirement /opt/coco/requirements-eval.lock

COPY entrypoint.py /opt/coco/entrypoint.py
COPY probe_runner.py /opt/coco/probe_runner.py
COPY search_client.py /opt/coco/search_client.py
COPY functional_runner.py /opt/coco/functional_runner.py
COPY dynamic_runner.py /opt/coco/dynamic_runner.py
COPY realism_runner.py /opt/coco/realism_runner.py
COPY oracles /opt/coco/oracles
COPY bigcodebench /opt/coco/bigcodebench
RUN chmod 0555 /opt/coco/entrypoint.py /opt/coco/probe_runner.py /opt/coco/search_client.py /opt/coco/functional_runner.py /opt/coco/dynamic_runner.py /opt/coco/realism_runner.py

# Explicit signal so `docker stop` sends SIGTERM to PID 1 and the entrypoint can
# forward it to the child process group before escalating to SIGKILL.
STOPSIGNAL SIGTERM

USER coco
WORKDIR /work

# No ENTRYPOINT/CMD: the trusted host supplies the registered entry argv.
