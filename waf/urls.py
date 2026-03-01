"""URL patterns for WAF module"""
from django.urls import path
from . import views

urlpatterns = [
    # Web dashboard
    path('', views.waf_dashboard_view, name='waf_dashboard_view'),

    # API endpoints
    path('dashboard/', views.waf_dashboard, name='waf_dashboard'),
    path('analyze/', views.analyze_request, name='analyze_request'),

    # Rules management
    path('rules/', views.list_rules, name='list_waf_rules'),
    path('rules/create/', views.create_rule, name='create_waf_rule'),
    path('rules/<int:rule_id>/toggle/', views.toggle_rule, name='toggle_waf_rule'),
    path('rules/<int:rule_id>/delete/', views.delete_rule, name='delete_waf_rule'),

    # IP management
    path('ip/block/', views.block_ip, name='block_waf_ip'),
    path('ip/unblock/', views.unblock_ip, name='unblock_waf_ip'),
    path('ip/blocked/', views.list_blocked_ips, name='list_blocked_ips'),
]
