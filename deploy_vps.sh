#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Jorise VPS Deploy Script
# VPS: 207.244.255.208
# Ejecutar como root o con sudo: bash deploy_vps.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

VPS_USER="jorise"
APP_DIR="/home/$VPS_USER/jorise"
PYTHON="$APP_DIR/.venv/bin/python"
PIP="$APP_DIR/.venv/bin/pip"

echo "======================================"
echo "  Jorise VPS Deploy - 207.244.255.208"
echo "======================================"

# ── 1. Dependencias del sistema ───────────────────────────────────────────────
echo "[1/7] Instalando dependencias del sistema..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git nginx supervisor \
    build-essential libssl-dev libffi-dev python3-dev

# ── 2. Crear usuario ──────────────────────────────────────────────────────────
echo "[2/7] Configurando usuario $VPS_USER..."
id -u $VPS_USER &>/dev/null || useradd -m -s /bin/bash $VPS_USER

# ── 3. Clonar / actualizar repo ───────────────────────────────────────────────
echo "[3/7] Descargando código..."
if [ -d "$APP_DIR" ]; then
    cd $APP_DIR && sudo -u $VPS_USER git pull
else
    sudo -u $VPS_USER git clone https://github.com/Vixy-beep/Jorise_android.git $APP_DIR
fi

# ── 4. Entorno virtual + dependencias ─────────────────────────────────────────
echo "[4/7] Instalando dependencias Python..."
cd $APP_DIR
sudo -u $VPS_USER python3 -m venv .venv
sudo -u $VPS_USER $PIP install -q --upgrade pip
sudo -u $VPS_USER $PIP install -q -r requirements.txt
sudo -u $VPS_USER $PIP install -q gunicorn

# ── 5. Variables de entorno ────────────────────────────────────────────────────
echo "[5/7] Configurando .env..."
if [ ! -f "$APP_DIR/.env" ]; then
    cat > $APP_DIR/.env << EOF
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
DEBUG=False
ALLOWED_HOSTS=207.244.255.208,localhost
CORS_ALLOWED_ORIGINS=http://207.244.255.208,http://207.244.255.208:8000
HTTPS_ENABLED=False
DJANGO_LOG_LEVEL=WARNING
EOF
    chown $VPS_USER:$VPS_USER $APP_DIR/.env
    chmod 600 $APP_DIR/.env
    echo "  ✅ .env creado con SECRET_KEY aleatorio"
else
    echo "  ℹ️  .env ya existe — no modificado"
fi

# ── 6. Migraciones + static ───────────────────────────────────────────────────
echo "[6/7] Migraciones y archivos estáticos..."
cd $APP_DIR
sudo -u $VPS_USER $PYTHON manage.py migrate --no-input
sudo -u $VPS_USER $PYTHON manage.py collectstatic --no-input --clear

# ── 7. Configurar nginx + supervisor ──────────────────────────────────────────
echo "[7/7] Configurando nginx y supervisor..."

# Gunicorn via supervisor
cat > /etc/supervisor/conf.d/jorise.conf << EOF
[program:jorise]
command=$APP_DIR/.venv/bin/gunicorn jorise.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 120
directory=$APP_DIR
user=$VPS_USER
autostart=true
autorestart=true
stderr_logfile=/var/log/jorise_err.log
stdout_logfile=/var/log/jorise_out.log
environment=PATH="$APP_DIR/.venv/bin"
EOF

# Nginx
cat > /etc/nginx/sites-available/jorise << EOF
server {
    listen 80;
    server_name 207.244.255.208;

    client_max_body_size 500M;

    location /static/ {
        alias $APP_DIR/staticfiles/;
        expires 30d;
    }

    location /media/ {
        alias $APP_DIR/media/;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120;
    }
}
EOF

ln -sf /etc/nginx/sites-available/jorise /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Iniciar servicios
supervisorctl reread && supervisorctl update && supervisorctl restart jorise
nginx -t && systemctl restart nginx

echo ""
echo "======================================"
echo "  ✅ Deploy completado!"
echo "  URL: http://207.244.255.208"
echo "  Logs: tail -f /var/log/jorise_err.log"
echo "======================================"
