FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY app_pages ./app_pages
COPY .streamlit ./.streamlit
COPY dashboard.py dashboard_api.py ./

RUN useradd --create-home --uid 1000 netsentinel
USER netsentinel

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
