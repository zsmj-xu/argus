ARG PYTHON_VERSION=3.11
ARG GO_VERSION=1.25.5
ARG OPENCODEREVIEW_VERSION=main
ARG OPENCODEREVIEW_COMMIT=1f5caf4d5b7d5324c6e4c836c971136e4010192e
ARG OPENCODEREVIEW_REPOSITORY=https://github.com/alibaba/open-code-review.git

FROM golang:${GO_VERSION}-bookworm AS ocr-builder
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

FROM python:${PYTHON_VERSION}-slim-bookworm AS python-builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY argus ./argus
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir --prefix=/install 'uvicorn>=0.30,<1' .

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARGUS_DATA_DIR=/var/lib/argus \
    OCR_BINARY=/usr/local/bin/ocr
WORKDIR /app
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/argus
COPY --from=python-builder /install /usr/local
COPY --from=ocr-builder /out/ocr /usr/local/bin/ocr
COPY argus ./argus
RUN useradd --create-home --uid 10001 argus \
    && chown -R argus:argus /app /var/lib/argus
USER argus
EXPOSE 8000
CMD ["uvicorn", "argus.service.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
