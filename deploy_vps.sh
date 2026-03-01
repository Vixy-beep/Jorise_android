#!/bin/bash
set -e
REPO="https://github.com/Vixy-beep/Jorise_android.git"
JORISE_DIR="/home/jorise/jorise"
JORISE_VENV="$JORISE_DIR/.venv"
GUARDIAN_DIR="/home/guardian/guardian"
GUARDIAN_VENV="$GUARDIAN_DIR/.venv"

echo "=== VPS Deploy: Jorise + Guardian ==="

echo "[1/8] Sistema..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git nginx supervisor build-essential libssl-dev libffi-dev python3-dev

echo "[2/8] Usuarios..."
id -u jorise   &>/dev/null || useradd -m -s /bin/bash jorise
id -u guardian &>/dev/null || useradd -m -s /bin/bash guardian
mkdir -p /home/jorise   && chown jorise:jorise     /home/jorise
mkdir -p /home/guardian && chown guardian:guardian /home/guardian

echo "[3/8] Jorise (main)..."
if [ -d "$JORISE_DIR/.git" ]; then
    cd "$JORISE_DIR"
    git fetch origin
    git reset --hard origin/main
    git clean -fd --exclude=.venv
else
    git clone -b main "$REPO" "$JORISE_DIR"
    chown -R jorise:jorise "$JORISE_DIR"
fi

echo "[4/8] Guardian (master)..."
if [ -d "$GUARDIAN_DIR/.git" ]; then
    cd "$GUARDIAN_DIR"
    git fetch origin
    git reset --hard origin/master
    git clean -fd --exclude=.venv
else
    git clone -b master "$REPO" "$GUARDIAN_DIR"
    chown -R guardian:guardian "$GUARDIAN_DIR"
fi

echo "[5/8] Python Jorise..."
python3 -m venv "$JORISE_VENV"
"$JORISE_VENV/bin/python" -m pip install -q --upgrade pip
"$JORISE_VENV/bin/python" -m pip install -q -r "$JORISE_DIR/requirements.txt"
"$JORISE_VENV/bin/python" -m pip install -q "gunicorn==21.2.0"
chown -R jorise:jorise "$JORISE_VENV"

echo "[6/8] Python Guardian..."
python3 -m venv "$GUARDIAN_VENV"
"$GUARDIAN_VENV/bin/python" -m pip install -q --upgrade pip
"$GUARDIAN_VENV/bin/python" -m pip install -q -r "$GUARDIAN_DIR/backend/requirements.txt"
chown -R guardian:guardian "$GUARDIAN_VENV"

echo "[7/8] .env y migraciones..."
if [ ! -f "$JORISE_DIR/.env" ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    printf "SECRET_KEY=%s\nDEBUG=False\nALLOWED_HOSTS=207.244.255.208,localhost\nCORS_ALLOWED_ORIGINS=http://207.244.255.208,http://207.244.255.208:8000\nHTTPS_ENABLED=False\n" "$SECRET" > "$JORISE_DIR/.env"
    chown jorise:jorise "$JORISE_DIR/.env"
    chmod 600 "$JORISE_DIR/.env"
fi
cd "$JORISE_DIR"
"$JORISE_VENV/bin/python" manage.py migrate --no-input
"$JORISE_VENV/bin/python" manage.py collectstatic --no-input --clear

if [ ! -f "$GUARDIAN_DIR/backend/.env" ]; then
    GSECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    printf "SECRET_KEY=%s\nDEBUG=False\nCORS_ORIGINS=[\"http://207.244.255.208\"]\n" "$GSECRET" > "$GUARDIAN_DIR/backend/.env"
    chown guardian:guardian "$GUARDIAN_DIR/backend/.env"
    chmod 600 "$GUARDIAN_DIR/backend/.env"
fi

echo "[8/8] Supervisor + Nginx..."
cat > /etc/supervisor/conf.d/jorise.conf << SUPEOF
[program:jorise]
command=${JORISE_VENV}/bin/gunicorn jorise.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 120
directory=${JORISE_DIR}
user=jorise
autostart=true
autorestart=true
stderr_logfile=/var/log/jorise_err.log
stdout_logfile=/var/log/jorise_out.log
environment=PATH="${JORISE_VENV}/bin"
SUPEOF

cat > /etc/supervisor/conf.d/guardian.conf << SUPEOF
[program:guardian]
command=${GUARDIAN_VENV}/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers 2
directory=${GUARDIAN_DIR}/backend
user=guardian
autostart=true
autorestart=true
stderr_logfile=/var/log/guardian_err.log
stdout_logfile=/var/log/guardian_out.log
environment=PATH="${GUARDIAN_VENV}/bin"
SUPEOF

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
rm -f /etc/nginx/sites-enabled/guardian

supervisorctl reread && supervisorctl update
supervisorctl restart jorise   2>/dev/null || supervisorctl start jorise
supervisorctl restart guardian 2>/dev/null || supervisorctl start guardian
nginx -t && systemctl restart nginx

echo ""
echo "=== LISTO ==="
echo " Jorise   -> http://207.244.255.208"
echo " Guardian -> http://207.244.255.208:8001/health"
echo " Logs: tail -f /var/log/jorise_err.log"