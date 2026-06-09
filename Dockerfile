FROM python:3.11-slim

# Libs système nécessaires pour WeasyPrint (export PDF)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Le port est fourni par Render via la variable $PORT
ENV PORT=8000
EXPOSE 8000

CMD uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000}
