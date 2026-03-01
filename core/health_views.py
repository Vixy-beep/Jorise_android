"""
Simple health check view for Jorise API
"""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """API Health Check - No authentication required"""
    return JsonResponse({
        'status': 'healthy',
        'service': 'Jorise SOC Backend API',
        'version': '2.0.0',
        'message': 'Backend operational',
        'available_endpoints': {
            'admin': '/admin/',
            'api_base': '/api/soc/<organization_id>/',
            'health': '/'
        }
    }, status=200)
