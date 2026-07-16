FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Railway injects $PORT; default to 8071 for local runs.
ENV PORT=8071
EXPOSE 8071

CMD ["python", "app.py"]
