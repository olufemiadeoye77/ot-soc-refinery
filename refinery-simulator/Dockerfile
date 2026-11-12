FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulator.py .

ENV MODBUS_PORT=5020
ENV TICK_INTERVAL=1.0

EXPOSE 5020

CMD ["python", "-u", "simulator.py"]
