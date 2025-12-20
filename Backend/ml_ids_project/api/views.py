# api/views.py
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
from .models import NetworkTraffic, ThreatIncident, ResponseRule, LogEntry
from .serializers import (
    NetworkTrafficSerializer,
    ThreatIncidentSerializer,
    ResponseRuleSerializer,
    LogEntrySerializer,
)

class NetworkTrafficViewSet(viewsets.ModelViewSet):
    queryset = NetworkTraffic.objects.all()
    serializer_class = NetworkTrafficSerializer

    @action(detail=False, methods=["get"], url_path="search")
    def search(self, request):
        q = request.query_params.get("q", "").strip()
        qs = self.get_queryset()
        if q:
            qs = qs.filter(
                Q(source_ip__icontains=q)
                | Q(destination_ip__icontains=q)
                | Q(protocol__icontains=q)
                | Q(status__icontains=q)
                | Q(severity__icontains=q)
            )
        qs = qs.order_by("-timestamp")[:500]
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["delete"], url_path="clear", authentication_classes=[], permission_classes=[])
    def clear(self, request):
        deleted_count, _ = NetworkTraffic.objects.all().delete()
        return Response({"deleted": deleted_count})

class ThreatIncidentViewSet(viewsets.ModelViewSet):
    queryset = ThreatIncident.objects.all()
    serializer_class = ThreatIncidentSerializer

class ResponseRuleViewSet(viewsets.ModelViewSet):
    queryset = ResponseRule.objects.all()
    serializer_class = ResponseRuleSerializer

class LogEntryViewSet(viewsets.ModelViewSet):
    queryset = LogEntry.objects.all()
    serializer_class = LogEntrySerializer