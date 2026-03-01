# Arquitectura — Guardian

## Principios de diseño

1. **Local-first**: la evaluación de riesgo ocurre en el dispositivo. El backend es opcional.
2. **Sin PII**: nunca se transmiten mensajes, fotos, ubicación exacta ni identificadores reales.
3. **Sin fricción en riesgo bajo**: el 95%+ de las sesiones normales pasan sin interrupción.
4. **Lenguaje simple**: todos los mensajes al usuario están escritos para personas no técnicas.

---

## Componentes

```
┌─────────────────────────────────────────────────────┐
│  ANDROID APP                                        │
│                                                     │
│  SignalCollector          →  lee señales pasivas    │
│  RiskEngine (local)       →  scoring sin backend    │
│  GuardianApiClient        →  sync con backend       │
│  GuardianAccessibilityService  →  overlays/scam     │
│                                                     │
│  UI (Jetpack Compose)                               │
│   ├── MainActivity (dashboard)                      │
│   └── AlertActivity (aviso de riesgo)               │
└─────────────────────────────────────────────────────┘
                      │  HTTPS
                      ▼
┌─────────────────────────────────────────────────────┐
│  BACKEND (FastAPI)                                  │
│                                                     │
│  POST /api/v1/evaluate   →  risk score remoto       │
│  GET  /api/v1/rules      →  sync de reglas          │
│  POST /api/v1/report     →  eventos anónimos        │
│                                                     │
│  ScoringEngine           →  mismas reglas que app   │
└─────────────────────────────────────────────────────┘
```

---

## Flujo de evaluación

```
Usuario intenta acción sensible
      ↓
SignalCollector.collect()
      ↓
RiskEngine.evaluate(snapshot)      ← local, sin red necesaria
      ↓
 ┌─────────────────────────────┐
 │  score ≤ 30 → LOW           │  → continúa sin interrupción
 │  score 31–60 → MEDIUM       │  → alerta + delay 5s
 │  score 61–80 → HIGH         │  → validación extra
 │  score > 80 → CRITICAL      │  → bloqueo temporal
 └─────────────────────────────┘
      ↓ (si hay red)
GuardianApiClient.evaluate()       ← confirmación remota (opcional)
      ↓
Resultado final al usuario
```

---

## Señales recolectadas

| Señal | Método Android | Riesgo |
|---|---|---|
| SSID desconocido | `WifiManager.ConnectionInfo` | Medio |
| DNS no estándar | `LinkProperties` | Medio |
| TLS inválido | `SSLSocket` / interceptor | Alto |
| VPN activa | `NetworkCapabilities.TRANSPORT_VPN` | Bajo |
| Overlay activo | `AccessibilityService.onAccessibilityEvent` | Alto |
| Permiso sensible nuevo | `PackageManager` | Medio |
| App desconocida en foco | `UsageStatsManager` | Medio |
| Developer options | `Settings.Global` | Bajo |
| Hora inusual | `Calendar` | Bajo |

---

## Decisiones técnicas

- **No Retrofit en MVP**: cliente HTTP con stdlib para mantener dependencias mínimas
- **No Room en MVP**: SharedPreferences para datos simples (redes conocidas, contadores)
- **FastAPI en lugar de Spring**: menor overhead, misma velocidad de desarrollo, compatible con equipo Python
- **SQLite en desarrollo**: migrar a PostgreSQL para producción
