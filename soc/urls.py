"""URL patterns for SOC module"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.soc_dashboard, name='soc_dashboard'),
    path('html/', views.soc_dashboard_html, name='soc_dashboard_html'),
    path('timeline/', views.get_events_timeline, name='events_timeline'),
]
