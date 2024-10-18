# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=async_app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
ENV FLASK_ENV=production


# Set work directory
WORKDIR /app

# Install system dependencies (optional)
# Only include if your project requires additional system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY async_app.py /app/
COPY static/ /app/static/
COPY templates/ /app/templates/

# Add a non-root user for better security
RUN useradd -m appuser
USER appuser

# Expose the port your app runs on
EXPOSE 5000

# Define the command to run your app using Gunicorn
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]