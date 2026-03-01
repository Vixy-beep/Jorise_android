"""
URL Configuration for Jorise v2 - Enterprise SOC
FULL PRODUCTION ROUTES - API Backend
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from core.health_views import health_check

# Optional: Import views only if needed
try:
    from core.auth_views import login_view, register_view, logout_view
    from core.dashboard_views import dashboard_view, subscription_management, settings_view, threat_map_data
except ImportError:
    login_view = register_view = logout_view = None
    dashboard_view = subscription_management = settings_view = threat_map_data = None

urlpatterns = [
    # API Health Check
    path('', health_check, name='api_health'),
    
    # Django Admin
    path('admin/', admin.site.urls),
    
    # Module dashboards (optional - for web interface)
    path('siem/', include('siem.urls')),
    path('edr/', include('edr.urls')),
    path('waf/', include('waf.urls')),
    path('sandbox/', include('sandbox.urls')),
    path('reports/', include('reports.urls')),
    path('risk/', include('risk.urls')),
    
    # API endpoints
    path('api/soc/<uuid:org_id>/', include('soc.urls')),

    # Training module (PCAP / CSV)
    path('training/', include('training.urls')),

    # Training REST API
    path('api/training/', include('training.api_urls')),
]

# Add auth routes if views are available
if login_view:
    urlpatterns.extend([
        path('login/', login_view, name='login'),
        path('register/', register_view, name='register'),
        path('logout/', logout_view, name='logout'),
        path('dashboard/', dashboard_view, name='dashboard'),
        path('subscription/', subscription_management, name='subscription_management'),
        path('settings/', settings_view, name='settings'),
        path('api/threat-map/', threat_map_data, name='threat_map_data'),
    ])

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
