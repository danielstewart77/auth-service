FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./
COPY db/schema.sql ./db/schema.sql

ENV AUTH_HOST=0.0.0.0

CMD ["python", "server.py"]
