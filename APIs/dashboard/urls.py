from django.urls import path
from . import views

urlpatterns = [
    path('stats/', views.dashboard_stats, name='dashboard_stats'),
    path('threats/', views.threat_activity, name='threat_activity'),
    path('metrics/', views.security_metrics, name='security_metrics'),
    path('health/', views.system_health, name='system_health'),
]