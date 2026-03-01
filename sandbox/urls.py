"""URL patterns for Sandbox module"""
from django.urls import path
from . import views

urlpatterns = [
    # Web dashboard
    path('', views.sandbox_dashboard_view, name='sandbox_dashboard_view'),
    
    # API endpoints
    path('dashboard/', views.sandbox_dashboard, name='sandbox_dashboard'),
    path('submit/', views.submit_file, name='submit_file'),
    path('analysis/<uuid:analysis_id>/', views.get_analysis, name='get_analysis'),
]
