from django.urls import pathfrom django.urls import path

from . import viewsfrom . import views



app_name = 'reports'urlpatterns = [

    path('', views.reports_list, name='reports_list'),

urlpatterns = [    path('generate/', views.generate_report, name='generate_report'),

    path('', views.report_dashboard, name='dashboard'),    path('view/<int:report_id>/', views.view_report, name='view_report'),

    path('export/<int:report_id>/', views.export_json, name='export_json'),    path('delete/<int:report_id>/', views.delete_report, name='delete_report'),

]]