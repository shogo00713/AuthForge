FROM python:3.11-slim

WORKDIR /app

COPY server.py .
COPY templates ./templates
COPY certs ./certs

ENV PYTHONUNBUFFERED=1

CMD ["python", "server.py"]