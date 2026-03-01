"""URL patterns for Risk Management module"""
from django.urls import path
from . import views

urlpatterns = [
    # Web dashboard
    path('', views.risk_dashboard_view, name='risk_dashboard_view'),

    # Stats API
    path('api/stats/', views.risk_stats, name='risk_stats'),

    # Risks CRUD
    path('api/risks/', views.list_risks, name='list_risks'),
    path('api/risks/create/', views.create_risk, name='create_risk'),
    path('api/risks/<int:risk_id>/update/', views.update_risk, name='update_risk'),
    path('api/risks/<int:risk_id>/delete/', views.delete_risk, name='delete_risk'),

    # Assets CRUD
    path('api/assets/', views.list_assets, name='list_assets'),
    path('api/assets/create/', views.create_asset, name='create_asset'),
    path('api/assets/<int:asset_id>/delete/', views.delete_asset, name='delete_asset'),

    # Vulnerabilities CRUD
    path('api/vulns/', views.list_vulnerabilities, name='list_vulnerabilities'),
    path('api/vulns/create/', views.create_vulnerability, name='create_vulnerability'),
    path('api/vulns/<int:vuln_id>/update/', views.update_vulnerability, name='update_vulnerability'),
    path('api/vulns/<int:vuln_id>/delete/', views.delete_vulnerability, name='delete_vulnerability'),
]
