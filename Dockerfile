# Use a lightweight Python base image
FROM python:3.11-slim

RUN apt-get update && apt-get install -y git nodejs npm && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

# Install express directly without package.json
RUN npm install -g express

EXPOSE 8080

CMD ["sh", "-c", "node index.js & python bot.py"]
