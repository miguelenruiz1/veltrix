#!/bin/bash

echo "🔄 Esperando a que PostgreSQL esté lista..."

# Espera hasta que el contenedor veltrix-auth-db abra el puerto 5432
until nc -z veltrix-auth-db 5432; do
  echo "⏳ Esperando conexión con la base de datos..."
  sleep 1
done

echo "✅ PostgreSQL está lista. Iniciando FastAPI..."

# Lanza FastAPI con Uvicorn
exec uvicorn src.main:app --host 0.0.0.0 --port 8000
