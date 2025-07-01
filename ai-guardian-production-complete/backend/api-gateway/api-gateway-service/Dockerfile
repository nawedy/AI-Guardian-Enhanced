# Phase 1: Create a builder with all the dependencies
FROM python:3.11-slim as builder

WORKDIR /app

# Upgrade pip
RUN pip install --upgrade pip

# Copy and install dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels -r requirements.txt


# Phase 2: Create the final production image
FROM python:3.11-slim

WORKDIR /app

# Copy the dependencies from the builder
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

# Copy the application source code
COPY ./src .

# Expose the port the app runs on
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /app

# Run the application with Gunicorn
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:8000", "main:app"] 