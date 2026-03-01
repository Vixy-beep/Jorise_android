"""URL patterns for EDR module"""
from django.urls import path
from . import views

urlpatterns = [
    # Web dashboard
    path('', views.edr_dashboard_view, name='edr_dashboard_view'),
    
    # API endpoints
    path('dashboard/', views.edr_dashboard, name='edr_dashboard'),
    path('register/', views.register_agent, name='register_agent'),
    path('agent/<uuid:agent_id>/heartbeat/', views.agent_heartbeat, name='agent_heartbeat'),
    path('agent/<uuid:agent_id>/report-process/', views.report_process, name='report_process'),
]
