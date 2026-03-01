# Guardian — Context-Aware Pre-Authentication Layer (3FA)

> **MVP v0.1** — Asistente de seguridad para usuarios no técnicos (adultos mayores, usuarios en riesgo).  
> Evalúa contexto *antes* del 2FA para reducir estafas y accesos sospechosos.

---

## Concepto

```
[ Acción sensible del usuario ]
           │
           ▼
┌──────────────────────────────┐
│  GUARDIAN — Capa 3FA         │
│  Evaluación contextual       │
│                              │
│  • Dispositivo conocido?     │
│  • Red segura? (DNS/TLS)     │
│  • Comportamiento normal?    │
│  • Permisos sospechosos?     │
│  • Señales de scam activas?  │
└──────────────────────────────┘
           │
     [ Risk Score ]
           │
    ┌──────┴──────┬──────────────┐
  BAJO          MEDIO           ALTO
    │              │               │
  Pasa          Aviso           Fricción
  normal      + delay          + validación extra
    │              │               │
    └──────────────┴───────────────┘
                   │
              [ 2FA normal ]
```

---

## Estructura del repositorio

```
guardian/
├── backend/          # FastAPI — Risk Engine + API de reglas
├── android/          # App Android (Kotlin) — Análisis local + UI
└── docs/             # Arquitectura, flujos, decisiones técnicas
```

---

## Stack

| Capa | Tecnología |
|---|---|
| Backend API | Python 3.12 + FastAPI |
| Base de datos | PostgreSQL (prod) / SQLite (dev) |
| Android | Kotlin + Jetpack Compose |
| Comunicación | REST/JSON (HTTPS) |
| Despliegue | Docker + Render / Railway |

---

## Inicio rápido — Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API disponible en `http://localhost:8000`  
Docs interactivos en `http://localhost:8000/docs`

---

## Inicio rápido — Android

1. Abrir `android/` en Android Studio (Giraffe o superior)
2. Configurar `android/app/src/main/res/values/config.xml` con la URL del backend
3. Run en emulador API 29+

---

## Señales que analiza el MVP

| Señal | Fuente | Riesgo |
|---|---|---|
| Red WiFi desconocida | WifiManager | Medio |
| DNS no estándar | NetworkInfo | Medio |
| Certificado TLS inválido | SSL Socket | Alto |
| Overlay/popup sospechoso | AccessibilityService | Alto |
| Permiso sensible recién concedido | PackageManager | Medio |
| Login desde ubicación inusual | Historial local | Alto |
| Patrón de uso fuera de horario | Historial local | Bajo/Medio |

---

## Niveles de riesgo

| Score | Nivel | Acción |
|---|---|---|
| 0–30 | 🟢 BAJO | Flujo normal |
| 31–60 | 🟡 MEDIO | Aviso en lenguaje simple + delay 5s |
| 61–80 | 🟠 ALTO | Validación extra (PIN / biométrico) |
| 81–100 | 🔴 CRÍTICO | Bloqueo temporal + notificación |

---

## Privacidad

- **Sin lectura de contenido**: no se leen mensajes, fotos ni datos personales
- **Evaluación local primero**: el score se calcula en el dispositivo
- **Backend solo recibe**: señales agregadas anonimizadas (no PII)
- **Sin tracking de ubicación continua**: solo se usa el contexto de la sesión actual

---

## Roadmap MVP

- [ ] Android: colector de señales de red (WiFi, DNS, TLS)
- [ ] Android: colector de señales de dispositivo (permisos, overlays)
- [ ] Android: motor de scoring local (reglas)
- [ ] Android: UI de alerta en lenguaje simple
- [ ] Backend: API de reglas (GET /rules, POST /report)
- [ ] Backend: agregación de patrones anónimos
- [ ] Integración: sincronización de reglas backend → app
- [ ] Demo: flujo completo con caso de scam simulado

---

## Deploy en VPS (Ubuntu 22.04 / 24.04)

### Primera vez

```bash
# 1. Clonar el repo en el VPS
git clone https://github.com/tu-usuario/guardian.git
cd guardian

# 2. Ejecutar el script de deploy (instala Python, nginx, crea systemd service)
sudo chmod +x deploy.sh
sudo ./deploy.sh

# 3. Editar variables de entorno
sudo nano /opt/guardian/.env

# 4. Iniciar el servicio
sudo systemctl start guardian

# Verificar estado
sudo systemctl status guardian

# Ver logs en tiempo real
sudo journalctl -u guardian -f
```

### Actualizar después de un push

```bash
git pull
sudo ./update.sh
```

### HTTPS con Let's Encrypt (opcional pero recomendado)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.tudominio.com
```

### Arquitectura en producción

```
Internet
   │ :443 (HTTPS)
   ▼
nginx  (reverse proxy + rate limit + TLS)
   │ :8000 (localhost only)
   ▼
uvicorn  (Guardian FastAPI, 2 workers)
   │
   ▼
SQLite / PostgreSQL
```

---

## Contribuir

1. Fork + rama `feature/tu-feature`
2. Los módulos están desacoplados — backend y android son independientes
3. Ver `docs/architecture.md` para decisiones de diseño
