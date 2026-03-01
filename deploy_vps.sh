#!/bin/bash
set -e
REPO="https://github.com/Vixy-beep/Jorise_android.git"

# ── Jorise (Django, port 8000, nginx port 80) ─────────────────────────────────
JORISE_USER="jorise"
JORISE_DIR="/home/jorise/jorise"
JORISE_VENV="$JORISE_DIR/.venv"

# ── Guardian (FastAPI, port 8001, Android API) ────────────────────────────────
GUARDIAN_USER="guardian"
GUARDIAN_DIR="/home/guardian/guardian"
GUARDIAN_VENV="$GUARDIAN_DIR/.venv"

echo "=== VPS Deploy: Jorise + Guardian ==="

# ── 1. Sistema ────────────────────────────────────────────────────────────────
echo "[1/8] Instalando dependencias del sistema..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git nginx supervisor \
    build-essential libssl-dev libffi-dev python3-dev

# ── 2. Usuarios ───────────────────────────────────────────────────────────────
echo "[2/8] Configurando usuarios..."
id -u "$JORISE_USER" &>/dev/null    || useradd -m -s /bin/bash "$JORISE_USER"
id -u "$GUARDIAN_USER" &>/dev/null  || useradd -m -s /bin/bash "$GUARDIAN_USER"

# ── 3. Clonar / actualizar Jorise (branch main) ───────────────────────────────
echo "[3/8] Descargando Jorise (main)..."
if [ -d "$JORISE_DIR/.git" ]; then
    cd "$JORISE_DIR"
    sudo -u "$JORISE_USER" git fetch origin
    sudo -u "$JORISE_USER" git reset --hard origin/main
    sudo -u "$JORISE_USER" git clean -fd
else
    sudo -u "$JORISE_USER" git clone -b main "$REPO" "$JORISE_DIR"
fi
echo "  Archivos: $(ls $JORISE_DIR | tr '\n' ' ')"

# ── 4. Clonar / actualizar Guardian (branch master) ───────────────────────────
echo "[4/8] Descargando Guardian (master)..."
if [ -d "$GUARDIAN_DIR/.git" ]; then
    cd "$GUARDIAN_DIR"
    sudo -u "$GUARDIAN_USER" git fetch origin
    sudo -u "$GUARDIAN_USER" git reset --hard origin/master
    sudo -u "$GUARDIAN_USER" git clean -fd
else
    sudo -u "$GUARDIAN_USER" git clone -b master "$REPO" "$GUARDIAN_DIR"
fi

# ── 5. Python: Jorise ─────────────────────────────────────────────────────────
echo "[5/8] Instalando Python Jorise..."
[ ! -x "$JORISE_VENV/bin/python" ] && sudo -u "$JORISE_USER" python3 -m venv "$JORISE_VENV"
sudo -u "$JORISE_USER" "$JORISE_VENV/bin/pip" install -q --upgrade pip
sudo -u "$JORISE_USER" "$JORISE_VENV/bin/pip" install -q -r "$JORISE_DIR/requirements.txt"
sudo -u "$JORISE_USER" "$JORISE_VENV/bin/pip" install -q "gunicorn==21.2.0"

# ── 6. Python: Guardian ───────────────────────────────────────────────────────
echo "[6/8] Instalando Python Guardian..."
[ ! -x "$GUARDIAN_VENV/bin/python" ] && sudo -u "$GUARDIAN_USER" python3 -m venv "$GUARDIAN_VENV"
sudo -u "$GUARDIAN_USER" "$GUARDIAN_VENV/bin/pip" install -q --upgrade pip
sudo -u "$GUARDIAN_USER" "$GUARDIAN_VENV/bin/pip" install -q -r "$GUARDIAN_DIR/backend/requirements.txt"

# ── 7. .env: Jorise ───────────────────────────────────────────────────────────
echo "[7/8] Configurando .env..."
if [ ! -f "$JORISE_DIR/.env" ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    printf "SECRET_KEY=%s\nDEBUG=False\nALLOWED_HOSTS=207.244.255.208,localhost\nCORS_ALLOWED_ORIGINS=http://207.244.255.208,http://207.244.255.208:8000\nHTTPS_ENABLED=False\n" "$SECRET" > "$JORISE_DIR/.env"
    chown "$JORISE_USER:$JORISE_USER" "$JORISE_DIR/.env"
    chmod 600 "$JORISE_DIR/.env"
fi
cd "$JORISE_DIR"
sudo -u "$JORISE_USER" "$JORISE_VENV/bin/python" manage.py migrate --no-input
sudo -u "$JORISE_USER" "$JORISE_VENV/bin/python" manage.py collectstatic --no-input --clear

# .env Guardian
if [ ! -f "$GUARDIAN_DIR/backend/.env" ]; then
    GSECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    printf "SECRET_KEY=%s\nDEBUG=False\nCORS_ORIGINS=[\"http://207.244.255.208\"]\n" "$GSECRET" > "$GUARDIAN_DIR/backend/.env"
    chown "$GUARDIAN_USER:$GUARDIAN_USER" "$GUARDIAN_DIR/backend/.env"
    chmod 600 "$GUARDIAN_DIR/backend/.env"
fi

# ── 8. Supervisor + Nginx ─────────────────────────────────────────────────────
echo "[8/8] Configurando supervisor y nginx..."

# Supervisor: Jorise
cat > /etc/supervisor/conf.d/jorise.conf << SUPEOF
[program:jorise]
command=${JORISE_VENV}/bin/gunicorn jorise.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 120
directory=${JORISE_DIR}
user=${JORISE_USER}
autostart=true
autorestart=true
stderr_logfile=/var/log/jorise_err.log
stdout_logfile=/var/log/jorise_out.log
environment=PATH="${JORISE_VENV}/bin"
SUPEOF

# Supervisor: Guardian
cat > /etc/supervisor/conf.d/guardian.conf << SUPEOF
[program:guardian]
command=${GUARDIAN_VENV}/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers 2
directory=${GUARDIAN_DIR}/backend
user=${GUARDIAN_USER}
autostart=true
autorestart=true
stderr_logfile=/var/log/guardian_err.log
stdout_logfile=/var/log/guardian_out.log
environment=PATH="${GUARDIAN_VENV}/bin"
SUPEOF

# Nginx: Jorise en puerto 80
cat > /etc/nginx/sites-available/jorise << NGINXEOF
server {
    listen 80;
    server_name 207.244.255.208;
    client_max_body_size 500M;
    location /static/ { alias ${JORISE_DIR}/staticfiles/; expires 30d; }
    location /media/  { alias ${JORISE_DIR}/media/; }
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
supervisorctl restart jorise   || supervisorctl start jorise
supervisorctl restart guardian || supervisorctl start guardian
nginx -t && systemctl restart nginx

echo ""
echo "=== Deploy completado! ==="
echo " Jorise  -> http://207.244.255.208"
echo " Guardian-> http://207.244.255.208:8001"
echo " Jorise logs:   tail -f /var/log/jorise_err.log"
echo " Guardian logs: tail -f /var/log/guardian_err.log"