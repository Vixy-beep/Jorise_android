#!/bin/bash
# Guardian — Script de actualización (cd al repo y ejecutar en el VPS)
# Uso: sudo ./update.sh

set -e

APP_DIR="/opt/guardian"
APP_USER="guardian"

echo "==> Copiando código actualizado..."
cp -r backend/. $APP_DIR/
chown -R $APP_USER:$APP_USER $APP_DIR

echo "==> Actualizando dependencias..."
$APP_DIR/.venv/bin/pip install -q -r $APP_DIR/requirements.txt

echo "==> Reiniciando servicio..."
systemctl restart guardian
systemctl status guardian --no-pager

echo ""
echo "✅ Actualización completa."
