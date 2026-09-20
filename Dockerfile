ARG PYTHON_IMAGE=python:3.11-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84
ARG GO_IMAGE=golang:1.25.5-bookworm@sha256:d9132cce84391efab786495288756d60e1da215b1f94e87860aeefc3d4c45b6d
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
ARG OPENCODEREVIEW_VERSION=codex/argus-aligned-refactor
ARG OPENCODEREVIEW_COMMIT=072808b6b0b12a1408b31889539c03878eff0f61
ARG OPENCODEREVIEW_REPOSITORY=https://github.com/zsmj-xu/open-code-review.git

FROM ${GO_IMAGE} AS ocr-builder
ARG OPENCODEREVIEW_VERSION
ARG OPENCODEREVIEW_COMMIT
ARG OPENCODEREVIEW_REPOSITORY
WORKDIR /build
COPY scripts/build-ocr.sh /usr/local/bin/build-ocr
RUN OCR_SOURCE_URL="$OPENCODEREVIEW_REPOSITORY" \
    OCR_VERSION="$OPENCODEREVIEW_VERSION" \
    OCR_COMMIT="$OPENCODEREVIEW_COMMIT" \
    OCR_OUTPUT=/out/ocr \
    /usr/local/bin/build-ocr

FROM ${NODE_IMAGE} AS frontend-builder
WORKDIR /build/frontend
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm run build

FROM ${PYTHON_IMAGE} AS python-builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY argus ./argus
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir --prefix=/install 'uvicorn>=0.30,<1' .

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARGUS_DATA_DIR=/var/lib/argus \
    ARGUS_FRONTEND_DIR=/app/frontend/dist \
    OCR_BINARY=/usr/local/bin/ocr
WORKDIR /app
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/argus
COPY --from=python-builder /install /usr/local
COPY --from=ocr-builder /out/ocr /usr/local/bin/ocr
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist
COPY argus ./argus
RUN useradd --create-home --uid 10001 argus \
    && chown -R argus:argus /app /var/lib/argus
USER argus
EXPOSE 8000
CMD ["uvicorn", "argus.service.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
