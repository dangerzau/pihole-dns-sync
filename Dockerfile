FROM python:3.11-slim

WORKDIR /app

COPY app.py /app/

RUN pip install --no-cache-dir docker requests prometheus_client

EXPOSE 8000

CMD ["python", "app.py"]
