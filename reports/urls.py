from django.urls import path
from . import views

urlpatterns = [
    path('', views.reports_list, name='reports_list'),
    path('generate/', views.generate_report, name='generate_report'),
    path('view/<int:report_id>/', views.view_report, name='view_report'),
    path('delete/<int:report_id>/', views.delete_report, name='delete_report'),
]