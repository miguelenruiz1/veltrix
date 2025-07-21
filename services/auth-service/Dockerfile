FROM python:3.11-slim

# Crear directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema necesarias

RUN apt-get update && apt-get install -y netcat-openbsd && apt-get clean



# Copiar código fuente
COPY ./src /app/src
COPY requirements.txt .
COPY entrypoint.sh .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Asegurar que el entrypoint sea ejecutable
RUN chmod +x /app/entrypoint.sh

# Exponer el puerto por defecto
EXPOSE 8000

# Ejecutar el entrypoint personalizado
ENTRYPOINT ["/app/entrypoint.sh"]
