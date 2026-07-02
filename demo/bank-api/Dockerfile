FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Railway injects $PORT; default to 8070 for local runs.
ENV PORT=8070
EXPOSE 8070

CMD ["python", "app.py"]
