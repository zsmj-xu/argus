FROM python:3.11-slim

WORKDIR /flowmart
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV VULN=1
EXPOSE 5000
CMD ["python", "app.py"]
