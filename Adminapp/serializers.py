from rest_framework import serializers

from rest_framework import serializers, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication


import logging

from Doctors.models import Document

logger = logging.getLogger(__name__)

class DocumentVerificationSerializer(serializers.Serializer):
    document_ids = serializers.ListField(
        child=serializers.IntegerField(), 
        allow_empty=False,
        required=True
    )
    doctor_id = serializers.IntegerField(required=True)


