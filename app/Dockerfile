FROM python:3.11-slim-bullseye

WORKDIR /app

# Dépendances système
RUN apt-get update \
 && apt-get install --no-install-recommends -y libpq-dev gcc \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Installer les dépendances en premier (cache Docker)
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]
