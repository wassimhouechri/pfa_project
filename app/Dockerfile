FROM python:3.11-slim-bullseye

WORKDIR /app

# Dépendances système
RUN apt-get update \
 && apt-get install --no-install-recommends -y libpq-dev gcc curl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copier l'application
COPY . .

# Créer un utilisateur non-root
RUN useradd --create-home --shell /bin/bash appuser \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Commande de démarrage avec vérification
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:5000 --worker-class gevent --workers 1 --timeout 120 --access-logfile - --error-logfile - app:app"]
