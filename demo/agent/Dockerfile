FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Railway injects $PORT; default to 8000 for local runs.
ENV PORT=8000
EXPOSE 8000

# Start the AgentCore-compatible HTTP host (serves UI + /invocations + /ping).
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
