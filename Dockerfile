FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for lxml
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY app/ ./app/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Temp directory for job files
RUN mkdir -p /tmp/stig-parser-jobs
ENV STIG_TEMP_DIR=/tmp/stig-parser-jobs

EXPOSE 5000

CMD ["python", "-m", "flask", "--app", "app.web:create_app", "run", "--host", "0.0.0.0", "--port", "5000"]
