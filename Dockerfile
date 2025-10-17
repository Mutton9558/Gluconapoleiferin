# Use a lightweight Python image
FROM python:3.11-slim

# Install curl, git, and Node.js 20
RUN apt-get update && apt-get install -y curl git && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Node dependencies (local install)
RUN npm install express

# Expose port 8080 for Fly.io
EXPOSE 8080

# Start both the HTTP server and Discord bot
CMD ["sh", "-c", "node index.js & python bot.py"]
