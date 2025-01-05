# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libpq-dev \
    curl && \
    apt-get clean

# Set the working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=fanaSystem.settings

# Expose the port your app runs on
EXPOSE 8080

# Run the application
CMD ["gunicorn", "-b", ":8080", "fanaSystem.asgi:application", "-k", "uvicorn.workers.UvicornWorker", "--timeout", "120"]

ENV SECRET_KEY=your_default_secret_key

# Copy SQLite database file
COPY db.sqlite3 /app/db.sqlite3

