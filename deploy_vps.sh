#!/bin/bash
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Jorise VPS Deploy Script
# VPS: 207.244.255.208
# Ejecutar como root: bash deploy_vps.sh
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
set -e

VPS_USER="jorise"
APP_DIR="/home/$VPS_USER/jorise"
VENV="$APP_DIR/.venv"
PYTHON="$VENV/bin/python"
PIP="$VENV/bin/pip"
GUNICORN="$VENV/bin/gunicorn"

echo "======================================"
echo "  Jorise VPS Deploy - 207.244.255.208"
echo "======================================"

# â”€â”€ 1. Dependencias del sistema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo "[1/7] Instalando dependencias del sistema..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git nginx supervisor \
    build-essential libssl-dev libffi-dev python3-dev dos2unix

# â”€â”€ 2. Crear usuario â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo "[2/7] Configurando usuario $VPS_USER..."
id -u "$VPS_USER" &>/dev/null || useradd -m -s /bin/bash "$VPS_USER"

# â”€â”€ 3. Clonar / actualizar repo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo "[3/7] Descargando codigo..."
if [ -d "$APP_DIR/.git" ]; then
    echo "  Actualizando repo existente..."
    cd "$APP_DIR" && sudo -u "$VPS_USER" git pull
else
    sudo -u "$VPS_USER" git clone https://github.com/Vixy-beep/Jorise_android.git "$APP_DIR"
fi

# Convertir CRLF -> LF (archivos creados en Windows)
find "$APP_DIR" -name "*.py" -o -name "*.sh" | xargs dos2unix -q 2>/dev/null || true

# â”€â”€ 4. Entorno virtual + dependencias â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo "[4/7] Instalando dependencias Python..."

# Crear venv si no existe
if [ ! -x "$PYTHON" ]; then
    sudo -u "$VPS_USER" python3 -m venv "$VENV"
fi

sudo -u "$VPS_USER" "$PIP" install -q --upgrade pip
sudo -u "$VPS_USER" "$PIP" install -q -r "$APP_DIR/requirements.txt"
sudo -u "$VPS_USER" "$PIP" install -q "gunicorn==21.2.0"

# â”€â”€ 5. Variables de entorno â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo "[5/7] Configurando .env..."
if [ ! -f "$APP_DIR/.env" ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    cat > "$APP_DIR/.env" << ENVEOF
SECRET_KEY=$SECRET
DEBUG=False
ALLOWED_HOSTS=207.244.255.208,localhost
CORS_ALLOWED_ORIGINS=http://207.244.255.208,http://207.244.255.208:8000
HTTPS_ENABLED=False
DJANGO_LOG_LEVEL=WARNING
ENVEOF
    chown "$VPS_USER:$VPS_USER" "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "  .env creado con SECRET_KEY aleatorio"
else
    echo "  .env ya existe, no modificado"
fi

# â”€â”€ 6. Migraciones + static â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo "[6/7] Migraciones y archivos estaticos..."
cd "$APP_DIR"
sudo -u "$VPS_USER" "$PYTHON" manage.py migrate --no-input
sudo -u "$VPS_USER" "$PYTHON" manage.py collectstatic --no-input --clear

# â”€â”€ 7. Configurar nginx + supervisor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo "[7/7] Configurando supervisor y nginx..."

# Gunicorn via supervisor
cat > /etc/supervisor/conf.d/jorise.conf << SUPEOF
[program:jorise]
command=$GUNICORN jorise.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 120
directory=$APP_DIR
user=$VPS_USER
autostart=true
autorestart=true
stderr_logfile=/var/log/jorise_err.log
stdout_logfile=/var/log/jorise_out.log
environment=PATH="$VENV/bin"
SUPEOF

# Nginx
cat > /etc/nginx/sites-available/jorise << NGINXEOF
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
NGINXEOF

ln -sf /etc/nginx/sites-available/jorise /etc/nginx/sites-enabled/jorise
rm -f /etc/nginx/sites-enabled/default

# Iniciar servicios
supervisorctl reread && supervisorctl update
supervisorctl restart jorise || supervisorctl start jorise
nginx -t && systemctl restart nginx

echo ""
echo "======================================"
echo "  Deploy completado!"
echo "  URL: http://207.244.255.208"
echo "  Logs error:  tail -f /var/log/jorise_err.log"
echo "  Logs output: tail -f /var/log/jorise_out.log"
echo "======================================"
