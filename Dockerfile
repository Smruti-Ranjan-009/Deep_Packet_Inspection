# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: build the C++ dpi_engine binary
# ==============================================================================
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY CMakeLists.txt .
COPY src/ src/
COPY include/ include/

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --target dpi_engine -j"$(nproc)"

# ==============================================================================
# Stage 2: lean runtime image -- just the compiled binary + Python API
# ==============================================================================
FROM python:3.12-slim AS runtime

# Create a non-root user to run the service.
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Python dependencies first, so this layer is cached across code-only changes.
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The compiled engine from stage 1.
COPY --from=build /build/build/dpi_engine /usr/local/bin/dpi_engine
RUN chmod +x /usr/local/bin/dpi_engine

# The FastAPI wrapper.
COPY api/app/ app/

# A sample pcap so the container is immediately testable without needing
# Wireshark or any external file -- also useful for a future "try it with a
# sample capture" button on a landing page.
COPY test_dpi.pcap /app/sample/test_dpi.pcap

ENV DPI_ENGINE_BIN=/usr/local/bin/dpi_engine
ENV DPI_WORK_DIR=/tmp/dpi_jobs

RUN mkdir -p /tmp/dpi_jobs && chown -R appuser:appuser /app /tmp/dpi_jobs
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; port = os.environ.get('PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=3)" || exit 1

# Shell form (not exec form) so $PORT actually gets expanded at container
# start. Render injects PORT (defaulting to 10000 on their platform); we
# fall back to 8000 for local `docker run` where PORT isn't set.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
