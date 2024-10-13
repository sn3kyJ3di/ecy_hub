# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies (optional)
# Only include if your project requires additional system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Add a non-root user for better security
RUN useradd -m appuser
USER appuser

# Copy project files
COPY async_app.py /app/
COPY static/ /app/static/
COPY templates/ /app/templates/

# Expose the port your app runs on
EXPOSE 5000

# Define the command to run your app using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "async_app:app", "--workers", "4"]