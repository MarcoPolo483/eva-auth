FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.7.1

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

# Copy application code
COPY src/ ./src/
COPY tests/ ./tests/

# Install the package in editable mode
RUN poetry install --no-interaction --no-ansi

# Set Python path
ENV PYTHONPATH=/app/src

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "eva_auth.main:app", "--host", "0.0.0.0", "--port", "8000"]
