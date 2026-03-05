# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory within the container
WORKDIR /app

# Install system dependencies (useful for psycopg and other compiled packages)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file to the working directory
COPY backend/requirements.txt .

# Upgrade pip and install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the working directory
COPY backend/ .

# Expose the port (Railway provides the PORT env variable automatically)
EXPOSE 8080

# Command to run the application, defaulting to 8080 if PORT is not set
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
