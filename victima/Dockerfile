FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY comun/ ./comun/
COPY victima/victima.py ./victima/victima.py

# victima/datos y evidencias/ se montan como volúmenes desde el anfitrión
# (ver docker-compose.yml), así sobreviven al cierre del contenedor.
ENTRYPOINT ["python", "-u", "victima/victima.py"]
