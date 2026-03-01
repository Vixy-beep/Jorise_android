#!/bin/bash
set -e
VPS_USER="jorise"
APP_DIR="/home/$VPS_USER/jorise"
VENV="$APP_DIR/.venv"
PYTHON="$VENV/bin/python"
PIP="$VENV/bin/pip"
GUNICORN="$VENV/bin/gunicorn"

echo "Jorise VPS Deploy - 207.244.255.208"

echo "[1/7] Instalando dependencias..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git nginx supervisor build-essential libssl-dev libffi-dev python3-dev

echo "[2/7] Configurando usuario $VPS_USER..."
id -u "$VPS_USER" &>/dev/null || useradd -m -s /bin/bash "$VPS_USER"

echo "[3/7] Descargando codigo..."
if [ -d "$APP_DIR/.git" ]; then
    cd "$APP_DIR"
    sudo -u "$VPS_USER" git fetch origin
    sudo -u "$VPS_USER" git reset --hard origin/main
    sudo -u "$VPS_USER" git clean -fd
else
    sudo -u "$VPS_USER" git clone https://github.com/Vixy-beep/Jorise_android.git "$APP_DIR"
fi

echo "  Archivos en repo:"
ls "$APP_DIR/"

echo "[4/7] Instalando dependencias Python..."
if [ ! -x "$PYTHON" ]; then
    sudo -u "$VPS_USER" python3 -m venv "$VENV"
fi
sudo -u "$VPS_USER" "$PIP" install -q --upgrade pip
sudo -u "$VPS_USER" "$PIP" install -q -r "$APP_DIR/requirements.txt"
sudo -u "$VPS_USER" "$PIP" install -q "gunicorn==21.2.0"

echo "[5/7] Configurando .env..."
if [ ! -f "$APP_DIR/.env" ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    printf "SECRET_KEY=%s\nDEBUG=False\nALLOWED_HOSTS=207.244.255.208,localhost\nCORS_ALLOWED_ORIGINS=http://207.244.255.208,http://207.244.255.208:8000\nHTTPS_ENABLED=False\nDJANGO_LOG_LEVEL=WARNING\n" "$SECRET" > "$APP_DIR/.env"
    chown "$VPS_USER:$VPS_USER" "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "  .env creado"
else
    echo "  .env ya existe"
fi

echo "[6/7] Migraciones y static..."
cd "$APP_DIR"
sudo -u "$VPS_USER" "$PYTHON" manage.py migrate --no-input
sudo -u "$VPS_USER" "$PYTHON" manage.py collectstatic --no-input --clear

echo "[7/7] Configurando supervisor y nginx..."
cat > /etc/supervisor/conf.d/jorise.conf << SUPEOF
[program:jorise]
command=${VENV}/bin/gunicorn jorise.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 120
directory=${APP_DIR}
user=${VPS_USER}
autostart=true
autorestart=true
stderr_logfile=/var/log/jorise_err.log
stdout_logfile=/var/log/jorise_out.log
environment=PATH="${VENV}/bin"
SUPEOF

cat > /etc/nginx/sites-available/jorise << NGINXEOF
server {
    listen 80;
    server_name 207.244.255.208;
    client_max_body_size 500M;
    location /static/ { alias ${APP_DIR}/staticfiles/; expires 30d; }
    location /media/ { alias ${APP_DIR}/media/; }
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 120;
    }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/jorise /etc/nginx/sites-enabled/jorise
rm -f /etc/nginx/sites-enabled/default
supervisorctl reread && supervisorctl update
supervisorctl restart jorise || supervisorctl start jorise
nginx -t && systemctl restart nginx

echo "Deploy completado! http://207.244.255.208"