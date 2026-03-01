# 🛡️ Jorise Security Platform v2.0

> **Modern Cybersecurity Suite with API-First Architecture**

[![Django](https://img.shields.io/badge/Django-5.2+-092E20?logo=django)](https://djangoproject.com/)
[![DRF](https://img.shields.io/badge/DRF-3.14+-red?logo=django)](https://www.django-rest-framework.org/)
[![React](https://img.shields.io/badge/React-18+-61DAFB?logo=react)](https://reactjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?logo=postgresql)](https://postgresql.org/)

## 🏗️ **Project Structure**

```
Jorise/
├── 📁 Frontend/          # Modern React + Tailwind UI
├── 📁 Backend/           # Django Core & Security Logic  
├── 📁 APIs/              # REST API Endpoints
├── 📁 Docs/              # Project Documentation
└── 📁 shared/            # Shared Configuration
```

## ⚡ **Quick Start**

### Backend API Server
```bash
cd Backend/
pip install -r ../requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 8000
```

### Frontend (Coming Soon)
```bash
cd Frontend/
npm install
npm run dev
```

## 🔌 **API Endpoints**

### 🔐 Authentication
```
POST /api/v1/auth/login/      # JWT Login
POST /api/v1/auth/register/   # User Registration  
GET  /api/v1/auth/me/         # User Profile
```

### 📊 Dashboard
```
GET /api/v1/dashboard/stats/    # Security Statistics
GET /api/v1/dashboard/threats/  # Threat Activity
GET /api/v1/dashboard/health/   # System Health
```

### 🔒 Security
```
POST /api/v1/security/scan/file/ # File Scanning
POST /api/v1/security/scan/url/  # URL Analysis
GET  /api/v1/security/threats/   # Threat Management
```

## 🎯 **Features**

- ✅ **Real-time Threat Detection**
- ✅ **Advanced File Scanning** 
- ✅ **Security Dashboard & Analytics**
- ✅ **JWT Authentication**
- ✅ **RESTful API Architecture**
- ✅ **Modern Frontend (React + Tailwind)**
- ✅ **Enterprise Security Modules**

## 🚀 **Technology Stack**

**Backend:**
- Django 5.2+ & Django REST Framework
- PostgreSQL Database
- JWT Authentication
- Celery + Redis (Async Tasks)

**Frontend:**
- React 18+ with Hooks
- Tailwind CSS for Styling
- Axios HTTP Client
- Real-time Updates

**Security:**
- Python-based Malware Detection
- Network Monitoring
- Threat Intelligence
- SIEM Integration

## 📖 **Documentation**

- [API Documentation](./Docs/API_DOCUMENTATION.md)
- [Development Guide](./Docs/DEVELOPMENT.md)
- [Deployment Guide](./Docs/DEPLOYMENT.md)

## 🔧 **Development**

### Environment Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Setup database
cd Backend/
python manage.py migrate
python manage.py loaddata fixtures/sample_data.json

# Create admin user
python manage.py createsuperuser

# Run development server
python manage.py runserver 8000
```

### API Testing
```bash
# Get JWT token
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}'

# Use token for authenticated requests
curl -H "Authorization: Bearer your_jwt_token" \
  http://localhost:8000/api/v1/dashboard/stats/
```

## 🌐 **Deployment**

### Backend (Render.com)
```bash
# Build command
./build.sh

# Start command  
cd Backend && gunicorn jorise_v2_complete.wsgi:application
```

### Frontend (Netlify)
```bash
# Build command
npm run build

# Publish directory
dist/
```

## 📈 **Roadmap**

### Phase 1: Backend API ✅
- [x] Django REST Framework setup
- [x] Authentication system
- [x] Core security APIs
- [x] Database migration

### Phase 2: Frontend Development 🔄
- [ ] React application setup
- [ ] Dashboard components
- [ ] Security interfaces
- [ ] Real-time features

### Phase 3: Advanced Features 📋
- [ ] WebSocket integration
- [ ] Machine Learning models
- [ ] Advanced analytics
- [ ] Mobile application

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

**Jorise Security Platform** - Next Generation Cybersecurity Suite
