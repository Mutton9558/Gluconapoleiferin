# Use a lightweight Python base image
FROM python:3.11-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all project files
COPY . .

# Install dependencies if you have requirements.txt
# If not, you can skip this line
RUN pip install --no-cache-dir -r requirements.txt

# Run your bot
CMD ["python", "bot.py"]
