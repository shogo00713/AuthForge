FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY templates ./templates
COPY certs ./certs

ENV PYTHONUNBUFFERED=1

CMD ["python", "server.py"]