from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from datetime import datetime, timedelta
import psutil
from .serializers import (
    DashboardStatsSerializer,
    ThreatActivitySerializer,
    SecurityMetricSerializer,
    SystemHealthSerializer
)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    """Get main dashboard statistics"""
    
    # Mock data - Replace with real database queries
    stats_data = {
        'total_threats_blocked': 15847,
        'active_incidents': 3,
        'endpoints_protected': 234,
        'uptime': '99.8%',
        'threat_level': 'LOW',
        'last_scan_time': datetime.now()
    }
    
    serializer = DashboardStatsSerializer(stats_data)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_activity(request):
    """Get recent threat activity"""
    
    # Mock data - Replace with real queries
    activities = []
    for i in range(10):
        activities.append({
            'timestamp': datetime.now() - timedelta(hours=i),
            'threat_type': ['Malware', 'Phishing', 'DDoS', 'Intrusion'][i % 4],
            'severity': ['High', 'Medium', 'Low'][i % 3],
            'source_ip': f'192.168.1.{100 + i}',
            'status': ['Blocked', 'Quarantined', 'Investigating'][i % 3]
        })
    
    serializer = ThreatActivitySerializer(activities, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_metrics(request):
    """Get security performance metrics"""
    
    metrics = [
        {
            'metric_name': 'Threats Detected',
            'current_value': 1547,
            'previous_value': 1423,
            'percentage_change': 8.7,
            'trend': 'up'
        },
        {
            'metric_name': 'False Positives',
            'current_value': 12,
            'previous_value': 18,
            'percentage_change': -33.3,
            'trend': 'down'
        },
        {
            'metric_name': 'Response Time (ms)',
            'current_value': 245,
            'previous_value': 267,
            'percentage_change': -8.2,
            'trend': 'down'
        }
    ]
    
    serializer = SecurityMetricSerializer(metrics, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def system_health(request):
    """Get system health metrics"""
    
    try:
        # Get real system metrics
        health_data = {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_traffic': 0.0,  # Implement network monitoring
            'active_connections': len(psutil.net_connections()),
            'services_status': {
                'database': 'online',
                'api': 'online',
                'scanner': 'online',
                'firewall': 'online'
            }
        }
    except:
        # Fallback mock data
        health_data = {
            'cpu_usage': 23.5,
            'memory_usage': 67.2,
            'disk_usage': 45.8,
            'network_traffic': 125.3,
            'active_connections': 47,
            'services_status': {
                'database': 'online',
                'api': 'online',
                'scanner': 'online',
                'firewall': 'online'
            }
        }
    
    serializer = SystemHealthSerializer(health_data)
    return Response(serializer.data)