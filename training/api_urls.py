"""
URLs de la API REST del módulo de Entrenamiento - Jorise v2
"""

from django.urls import path
from . import api_views

urlpatterns = [
    path('models/',                  api_views.list_models,       name='api_list_models'),
    path('models/<uuid:model_id>/',  api_views.model_detail_api,  name='api_model_detail'),
    path('predict/pcap/',            api_views.predict_pcap_api,  name='api_predict_pcap'),
    path('predict/csv/',             api_views.predict_csv_api,   name='api_predict_csv'),
    path('jobs/',                    api_views.list_jobs,          name='api_list_jobs'),
    path('jobs/<uuid:job_id>/',      api_views.job_detail_api,     name='api_job_detail'),
    path('evaluate/',                api_views.evaluate_api,       name='api_evaluate'),
]
