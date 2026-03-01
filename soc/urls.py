"""URL patterns for SOC module"""
from django.urls import path
from . import views
from siem.views import siem_dashboard
from edr.views import edr_dashboard
from waf.views import (
    waf_dashboard, block_ip, unblock_ip, list_blocked_ips,
    list_rules, toggle_rule, delete_rule, create_rule,
)
from sandbox.views import sandbox_dashboard, submit_file

urlpatterns = [
    path('', views.soc_dashboard, name='soc_dashboard'),
    path('html/', views.soc_dashboard_html, name='soc_dashboard_html'),
    path('timeline/', views.get_events_timeline, name='events_timeline'),
    # Module dashboards (llamados desde las templates)
    path('siem/dashboard/', siem_dashboard, name='soc_siem_dashboard'),
    path('edr/dashboard/', edr_dashboard, name='soc_edr_dashboard'),
    path('waf/dashboard/', waf_dashboard, name='soc_waf_dashboard'),
    path('sandbox/dashboard/', sandbox_dashboard, name='soc_sandbox_dashboard'),
    path('sandbox/submit/', submit_file, name='soc_sandbox_submit'),
    # WAF IP & Rule management
    path('waf/ip/block/', block_ip, name='soc_waf_block_ip'),
    path('waf/ip/unblock/', unblock_ip, name='soc_waf_unblock_ip'),
    path('waf/ip/blocked/', list_blocked_ips, name='soc_waf_blocked_ips'),
    path('waf/rules/', list_rules, name='soc_waf_rules'),
    path('waf/rules/create/', create_rule, name='soc_waf_create_rule'),
    path('waf/rules/<int:rule_id>/toggle/', toggle_rule, name='soc_waf_toggle_rule'),
    path('waf/rules/<int:rule_id>/delete/', delete_rule, name='soc_waf_delete_rule'),
]
