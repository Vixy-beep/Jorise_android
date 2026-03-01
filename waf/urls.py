"""URL patterns for WAF module"""
from django.urls import path
from . import views

urlpatterns = [
    # Web dashboard
    path('', views.waf_dashboard_view, name='waf_dashboard_view'),
    
    # API endpoints
    path('dashboard/', views.waf_dashboard, name='waf_dashboard'),
    path('analyze/', views.analyze_request, name='analyze_request'),
    path('rules/create/', views.create_rule, name='create_waf_rule'),
]
