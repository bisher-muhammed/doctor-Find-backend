from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics, permissions, status
from django.contrib.auth import authenticate
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from Users.utils import generate_pdf,send_notification_user
from Doctors.models import DoctorProfile
from Doctors.serializers import DocumentSerializer
from django.contrib import messages
from Doctors.models import Document

import io

from rest_framework_simplejwt.authentication import JWTAuthentication


class AdminLogin(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        required_fields = ['email', 'password']

        if not all(field in data for field in required_fields):
            return Response({'detail': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = data.get('email')
            print('email',email)
            password = data.get('password')
            print('password:',password)

            if not email or not password:
                return Response({'detail': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(username=email, password=password)
            print('user:',user)

            if user is not None and user.is_superuser:
                refresh = RefreshToken.for_user(user)
                refresh['username'] = str(user.username)
                access_token = refresh.access_token
                refresh_token = str(refresh)
                print("user logined")

                content = {
                    'access_token': str(access_token),
                    'refresh_token': refresh_token,
                    'isAdmin': user.is_superuser,
                }
                return Response(content, status=status.HTTP_200_OK)
            

            elif user is not None and not user.is_superuser:
                return Response({'detail': 'This account is not a Superuser account'}, status=status.HTTP_401_UNAUTHORIZED)

            else:
                return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


import logging
logger = logging.getLogger(__name__)


class FetchDocuments(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DocumentSerializer

    def get_queryset(self):
        try:
            documents = Document.objects.select_related('doctor').all()
            logger.debug(f"Documents fetched: {documents}")
            return documents
        except Exception as e:
            logger.error(f"Error fetching documents: {str(e)}", exc_info=True)
            raise

    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching documents: {str(e)}", exc_info=True)
            return Response({'detail': 'An error occurred while fetching documents.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





logger = logging.getLogger(__name__)




import logging

logger = logging.getLogger(__name__)

class VerifyDocuments(generics.UpdateAPIView):
    """
    View to verify doctor profiles.
    """

    def get_object(self):
        raise NotImplementedError("This view does not handle single object retrieval.")

    def post(self, request, *args, **kwargs):
        logger.info("Received request to verify doctor profiles.")
        logger.info(f"User is superuser: {request.user.is_superuser}")

        if not request.user.is_superuser:
            logger.warning("Unauthorized attempt to verify documents by non-superuser.")
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        
        # Directly get data from the request
        document_ids = request.data.get('document_ids', [])
        doctor_id = request.data.get('doctor_id')

        # Validate the input
        if not document_ids or not doctor_id:
            return Response({'detail': 'Both document_ids and doctor_id are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the provided doctor ID exists in the DoctorProfile model
        if not DoctorProfile.objects.filter(id=doctor_id).exists():
            return Response({'doctor_id': 'Doctor does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if all document IDs exist and belong to the given doctor
        invalid_documents = [
            doc_id for doc_id in document_ids
            if not Document.objects.filter(id=doc_id, doctor_id=doctor_id).exists()
        ]

        if invalid_documents:
            return Response({
                'document_ids': f"The following document IDs are invalid or do not belong to the specified doctor: {invalid_documents}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Update the `is_verified` field in DoctorProfile
        updated_count = DoctorProfile.objects.filter(id=doctor_id).update(is_verified=True)
        logger.info(f"Doctor profiles updated successfully: {updated_count}")

        return Response({'message': f'Doctor profile with ID {doctor_id} has been marked as verified.'}, status=status.HTTP_200_OK)
