# Jorise Security Platform - API Documentation

## 🏗️ Architecture Overview

```
Frontend (React/Vue) ← HTTP/WebSocket → Backend (Django API) ← SQL → PostgreSQL
                                            ↓
                                      Security Engines
                                    (Python Libraries)
```

## 🔧 Technology Stack

### Backend
- **Django 5.2+** - Web framework
- **Django REST Framework** - API framework
- **PostgreSQL** - Database
- **JWT Authentication** - Stateless auth
- **Celery + Redis** - Async tasks

### Frontend (Coming Soon)
- **React/Vue.js** - UI framework
- **Tailwind CSS** - Styling
- **Axios** - HTTP client
- **Chart.js** - Data visualization

## 📡 API Endpoints

### Authentication
```
POST /api/v1/auth/login/        # User login (get JWT)
POST /api/v1/auth/refresh/      # Refresh JWT token
POST /api/v1/auth/register/     # User registration
POST /api/v1/auth/logout/       # Logout
GET  /api/v1/auth/profile/      # User profile
GET  /api/v1/auth/me/          # Current user info
```

### Dashboard
```
GET /api/v1/dashboard/stats/    # Main dashboard statistics
GET /api/v1/dashboard/threats/  # Recent threat activity
GET /api/v1/dashboard/metrics/  # Security performance metrics  
GET /api/v1/dashboard/health/   # System health status
```

### Security
```
POST /api/v1/security/scan/file/    # Upload & scan file
POST /api/v1/security/scan/url/     # Scan URL for threats
GET  /api/v1/security/scan/history/ # User scan history
GET  /api/v1/security/threats/      # Active threats list
GET  /api/v1/security/threats/{id}/ # Threat details
GET  /api/v1/security/protection/   # Protection status
GET  /api/v1/security/firewall/     # Firewall rules
```

## 🔐 Authentication Flow

### 1. Login
```javascript
POST /api/v1/auth/login/
{
  "username": "admin",
  "password": "secure_password"
}

Response:
{
  "access": "jwt_access_token",
  "refresh": "jwt_refresh_token",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@jorise.com"
  }
}
```

### 2. Authenticated Requests
```javascript
Headers: {
  "Authorization": "Bearer jwt_access_token"
}
```

### 3. Token Refresh
```javascript
POST /api/v1/auth/refresh/
{
  "refresh": "jwt_refresh_token"
}
```

## 📊 Example API Responses

### Dashboard Stats
```javascript
GET /api/v1/dashboard/stats/

{
  "total_threats_blocked": 15847,
  "active_incidents": 3,
  "endpoints_protected": 234,
  "uptime": "99.8%",
  "threat_level": "LOW",
  "last_scan_time": "2025-10-09T12:30:00Z"
}
```

### File Scan
```javascript
POST /api/v1/security/scan/file/
Content-Type: multipart/form-data
file: binary_file

{
  "file_name": "document.pdf",
  "file_size": 1024000,
  "file_hash": "sha256_hash",
  "threat_detected": false,
  "risk_level": "Low",
  "scan_time": "2025-10-09T12:30:00Z",
  "details": {
    "signatures_matched": 0,
    "reputation_score": 85
  }
}
```

## 🚀 Development Setup

### Backend Setup
```bash
cd Backend/
pip install -r ../requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 8000
```

### Frontend Setup (Coming Soon)
```bash
cd Frontend/
npm install
npm run dev
```

## 🔄 Migration Guide

### From Current System
1. **Keep all Django models** - Security logic preserved
2. **Remove HTML templates** - React will handle UI
3. **Add REST endpoints** - New API layer
4. **Configure CORS** - Allow frontend communication

### Database Migration
```bash
# Backup current SQLite
cp Backend/db.sqlite3 Backend/db.backup

# Setup PostgreSQL
# Update settings.py with PostgreSQL config
python manage.py migrate
```

## 📈 Next Steps

1. **Complete API endpoints** for all security modules
2. **Setup React frontend** with modern UI
3. **Implement real-time features** with WebSockets
4. **Add comprehensive testing**
5. **Deploy to production** (Render + Netlify)

---

**Jorise Security Platform v2.0** - Modern Cybersecurity Suite