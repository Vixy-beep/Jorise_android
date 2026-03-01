from rest_framework import serializers
# LAZY IMPORTS: Models se referencian como strings o se importan donde se usan
# from scan.models import *
# from reports.models import *
# from core.models import *

class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for dashboard statistics"""
    total_threats_blocked = serializers.IntegerField()
    active_incidents = serializers.IntegerField()
    endpoints_protected = serializers.IntegerField()
    uptime = serializers.CharField()
    threat_level = serializers.CharField()
    last_scan_time = serializers.DateTimeField()

class ThreatActivitySerializer(serializers.Serializer):
    """Serializer for threat activity data"""
    timestamp = serializers.DateTimeField()
    threat_type = serializers.CharField()
    severity = serializers.CharField()
    source_ip = serializers.IPAddressField()
    status = serializers.CharField()

class SecurityMetricSerializer(serializers.Serializer):
    """Serializer for security metrics"""
    metric_name = serializers.CharField()
    current_value = serializers.IntegerField()
    previous_value = serializers.IntegerField()
    percentage_change = serializers.FloatField()
    trend = serializers.CharField()  # 'up', 'down', 'stable'

class SystemHealthSerializer(serializers.Serializer):
    """Serializer for system health data"""
    cpu_usage = serializers.FloatField()
    memory_usage = serializers.FloatField()
    disk_usage = serializers.FloatField()
    network_traffic = serializers.FloatField()
    active_connections = serializers.IntegerField()
    services_status = serializers.DictField()