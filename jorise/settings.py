"""
Django settings for Jorise v2 - Enterprise SOC
"""

import os
import dj_database_url
from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY', default='django-insecure-change-this-in-production')

DEBUG = config('DEBUG', default=False, cast=bool)

# ALLOWED_HOSTS configuration
allowed_hosts_str = config('ALLOWED_HOSTS', default='')
if allowed_hosts_str:
    ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_str.split(',')]
else:
    ALLOWED_HOSTS = [
        'localhost',
        '127.0.0.1',
        '207.244.255.208',   # VPS principal
        'vineksec.com',
        'www.vineksec.com',
        '.vineksec.com',
        '.onrender.com',
        'jorise.vineksec.online',
    ]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party
    'rest_framework',
    'corsheaders',
    
    # Jorise Apps - FULL DEPLOYMENT READY
    # ✅ All apps properly configured with apps.py and lazy imports
    'core',      # Base models - must be first
    'scan',      # Scanning functionality
    'reports',   # Reporting system
    'soc',       # Security Operations Center
    'siem',      # Security Information Event Management
    'edr',       # Endpoint Detection Response
    'waf',       # Web Application Firewall
    'sandbox',   # Malware Sandbox Analysis
    'training',  # ML Training Engine (PCAP / CSV)
    'risk',      # Gestión de Riesgos TI — ISO 27005
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'jorise.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'jorise.wsgi.application'

# Database configuration with fallback
database_url = config('DATABASE_URL', default='')

# Force SQLite for now (PostgreSQL connection issues on Railway)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Alternative: Use PostgreSQL if connection works
# Uncomment when PostgreSQL is fixed
# if database_url:
#     try:
#         DATABASES = {
#             'default': dj_database_url.config(
#                 default=database_url,
#                 conn_max_age=600,
#                 conn_health_checks=True,
#             )
#         }
#     except Exception:
#         # Fallback to SQLite if PostgreSQL fails
#         DATABASES = {
#             'default': {
#                 'ENGINE': 'django.db.backends.sqlite3',
#                 'NAME': BASE_DIR / 'db.sqlite3',
#             }
#         }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static'] if os.path.exists(BASE_DIR / 'static') else []
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 100,
}

# CORS
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default=','.join([
        'http://localhost:4321',
        'http://localhost:3000',
        'http://207.244.255.208',
        'http://207.244.255.208:8000',
        'http://207.244.255.208:3000',
        'http://vineksec.com',
        'https://vineksec.com',
        'http://www.vineksec.com',
        'https://www.vineksec.com',
    ])
).split(',')

CORS_ALLOW_CREDENTIALS = True

# Celery
CELERY_BROKER_URL = config('REDIS_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('REDIS_URL', default='redis://localhost:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# AI Configuration
GEMINI_API_KEY = config('GEMINI_API_KEY', default='')
# Legacy support (commented out)
# OPENAI_API_KEY = config('OPENAI_API_KEY', default='')

# Threat Intelligence
VIRUSTOTAL_API_KEY = config('VIRUSTOTAL_API_KEY', default='')
ALIENVAULT_API_KEY = config('ALIENVAULT_API_KEY', default='')

# Stripe
STRIPE_PUBLIC_KEY = config('STRIPE_PUBLIC_KEY', default='')
STRIPE_SECRET_KEY = config('STRIPE_SECRET_KEY', default='')
STRIPE_WEBHOOK_SECRET = config('STRIPE_WEBHOOK_SECRET', default='')

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': config('DJANGO_LOG_LEVEL', default='INFO'),
        },
        'jorise': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    },
}

# Security
if not DEBUG:
    # Solo activar HTTPS redirect si hay SSL configurado
    _has_ssl = config('HTTPS_ENABLED', default=False, cast=bool)
    SECURE_SSL_REDIRECT = _has_ssl
    SESSION_COOKIE_SECURE = _has_ssl
    CSRF_COOKIE_SECURE = _has_ssl
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    # Proxy headers (necesario detrás de nginx)
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    USE_X_FORWARDED_HOST = True
