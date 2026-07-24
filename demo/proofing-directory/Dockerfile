FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Railway injects $PORT; default to 8075 for local runs.
ENV PORT=8075
EXPOSE 8075

CMD ["python", "app.py"]
