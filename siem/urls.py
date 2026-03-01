"""URL patterns for SIEM module"""
from django.urls import path
from . import views

urlpatterns = [
    # Web dashboard (template view)
    path('', views.siem_dashboard_view, name='siem_dashboard_view'),
    
    # API endpoints
    path('dashboard/', views.siem_dashboard, name='siem_dashboard'),
    path('ingest/', views.ingest_log, name='ingest_log'),
    path('report/', views.generate_report, name='siem_generate_report'),
]
