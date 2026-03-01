#!/bin/bash
# ============================================================
# Guardian — Script de deploy inicial en Ubuntu 22.04 / 24.04
# Ejecutar como root o con sudo en el VPS
#
# Uso:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
# ============================================================

set -e

APP_DIR="/opt/guardian"
APP_USER="guardian"
PYTHON="python3"
DOMAIN=""   # Opcional: dominio para el bloque nginx (ej: api.guardian.tudominio.com)

echo "==> Actualizando sistema..."
apt-get update -qq && apt-get upgrade -y -qq

echo "==> Instalando dependencias del sistema..."
apt-get install -y -qq python3 python3-pip python3-venv nginx git curl

echo "==> Creando usuario del servicio..."
id -u $APP_USER &>/dev/null || useradd --system --no-create-home --shell /bin/false $APP_USER

echo "==> Copiando código a $APP_DIR..."
mkdir -p $APP_DIR
cp -r backend/. $APP_DIR/
chown -R $APP_USER:$APP_USER $APP_DIR

echo "==> Creando entorno virtual..."
$PYTHON -m venv $APP_DIR/.venv
$APP_DIR/.venv/bin/pip install -q --upgrade pip
$APP_DIR/.venv/bin/pip install -q -r $APP_DIR/requirements.txt

echo "==> Configurando variables de entorno..."
if [ ! -f "$APP_DIR/.env" ]; then
    cp $APP_DIR/.env.example $APP_DIR/.env
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/change-me-in-production/$SECRET/" $APP_DIR/.env
    echo "  ⚠️  Edita $APP_DIR/.env con tu configuración real antes de iniciar el servicio."
fi

echo "==> Instalando servicio systemd..."
cp scripts/guardian.service /etc/systemd/system/guardian.service
systemctl daemon-reload
systemctl enable guardian

echo "==> Configurando nginx..."
cp scripts/guardian.nginx /etc/nginx/sites-available/guardian
ln -sf /etc/nginx/sites-available/guardian /etc/nginx/sites-enabled/guardian
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ""
echo "✅ Deploy completo."
echo "   Inicia el servicio con:  sudo systemctl start guardian"
echo "   Verifica el estado con:  sudo systemctl status guardian"
echo "   Logs en tiempo real:     sudo journalctl -u guardian -f"
echo ""
echo "   API disponible en: http://TU_IP/api/v1"
echo "   Docs:              http://TU_IP/docs"
