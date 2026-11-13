FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

ENV LOG_PATH=/var/ot/telemetry/zeek/conn.log
ENV ALERT_LOG=/var/ot/telemetry/ai-anomaly/alerts.jsonl

RUN mkdir -p /var/ot/telemetry/ai-anomaly

CMD ["python", "-u", "agent.py", "/var/ot/telemetry/zeek/conn.log"]
