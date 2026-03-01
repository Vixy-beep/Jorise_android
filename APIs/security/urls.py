from django.urls import path
from . import views

urlpatterns = [
    # Scan endpoints
    path('scan/file/', views.scan_file, name='scan_file'),
    path('scan/url/', views.scan_url, name='scan_url'),
    path('scan/history/', views.scan_history, name='scan_history'),
    
    # Threat management
    path('threats/', views.threat_list, name='threat_list'),
    path('threats/<int:pk>/', views.threat_detail, name='threat_detail'),
    
    # Protection status
    path('protection/status/', views.protection_status, name='protection_status'),
    path('firewall/rules/', views.firewall_rules, name='firewall_rules'),
]