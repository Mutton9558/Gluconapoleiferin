# Use a lightweight Python base image
FROM python:3.11-slim

# Install git (needed for pip install from GitHub, if any)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all project files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose a port for the dummy HTTP server
EXPOSE 8080

# Run your bot
CMD ["python", "bot.py"]
