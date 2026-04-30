FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        make \
        build-essential \
        libglib2.0-0 \
        libpango-1.0-0 \
        libharfbuzz0b \
        libpangoft2-1.0-0 \
        libpangocairo-1.0-0 \
        libfontconfig1 \
        libcairo2 \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY . .

RUN uv sync --frozen --no-dev

EXPOSE 8000

CMD ["sh", "-c", "uv run uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
