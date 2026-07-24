FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Railway injects $PORT; default to 8090 for local runs.
ENV PORT=8090
EXPOSE 8090

CMD ["python", "server.py"]
