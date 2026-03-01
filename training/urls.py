"""
URLs del módulo de Entrenamiento de Jorise v2
"""

from django.urls import path
from . import views

app_name = 'training'

urlpatterns = [
    path('',                             views.training_dashboard, name='dashboard'),
    path('upload/',                      views.upload_dataset,     name='upload_dataset'),
    path('start/',                       views.start_training,     name='start_training'),
    path('job/<uuid:job_id>/status/',    views.job_status,         name='job_status'),
    path('model/<uuid:model_id>/',       views.model_detail,       name='model_detail'),
    path('dataset/<uuid:dataset_id>/delete/', views.delete_dataset, name='delete_dataset'),
    path('datasets/',                    views.dataset_list,       name='dataset_list'),
]
