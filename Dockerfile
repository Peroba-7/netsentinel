FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY app_pages ./app_pages
COPY .streamlit ./.streamlit
COPY dashboard.py dashboard_api.py dashboard_nav.py dashboard_format.py ./
COPY alembic.ini ./
COPY migrations ./migrations

RUN useradd --create-home --uid 1000 netsentinel
USER netsentinel

EXPOSE 8000

# Aplica as migrações antes de arrancar a API; se falharem, a API não arranca.
# O dashboard usa a mesma imagem com outro comando, por isso não corre migrações.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
