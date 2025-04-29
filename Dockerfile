FROM python:3.12-slim

WORKDIR /app

COPY app.py .

RUN pip install docker requests prometheus_client

CMD ["python", "app.py"]
