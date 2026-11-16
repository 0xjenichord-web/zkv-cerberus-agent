FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y nodejs npm && npm install -g snarkjs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3000
CMD ["gunicorn", "--bind", "0.0.0.0:3000", "cerberus_core:app"]
