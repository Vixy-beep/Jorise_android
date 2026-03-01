from django.urls import path
from . import views

urlpatterns = [
    path('', views.reports_list, name='reports_list'),
    path('generate/', views.generate_report, name='generate_report'),
    path('view/<int:report_id>/', views.view_report, name='view_report'),
    path('delete/<int:report_id>/', views.delete_report, name='delete_report'),
    path('ml-eval/', views.ml_eval_report, name='ml_eval_report'),
    path('ml-eval/run/', views.run_ml_eval, name='run_ml_eval'),
]