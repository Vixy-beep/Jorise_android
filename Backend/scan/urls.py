from django.urls import path
from . import views

app_name = 'scan'

urlpatterns = [
    path('', views.advanced_scan_dashboard, name='dashboard'),
    path('multi-engine/', views.multi_engine_scan, name='multi_engine'),
    path('behavioral/', views.behavioral_analysis, name='behavioral'),
    path('threat-hunting/', views.threat_hunting, name='threat_hunting'),
]