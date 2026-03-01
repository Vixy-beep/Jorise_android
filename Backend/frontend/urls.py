from django.urls import path
from . import views

app_name = 'frontend'

urlpatterns = [
    path('', views.SecurityDashboardView.as_view(), name='security_dashboard'),
    path('api/threat-intelligence/', views.threat_intelligence_api, name='threat_api'),
    path('compliance/', views.security_compliance_report, name='compliance'),
    path('incidents/', views.incident_response_center, name='incidents'),
]