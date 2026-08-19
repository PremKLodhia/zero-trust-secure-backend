FROM python:3.13-slim

WORKDIR /app

# Install build essentials for C extensions if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY README.md .
COPY src/ ./src
COPY policies/ ./policies
COPY scripts/ ./scripts

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
