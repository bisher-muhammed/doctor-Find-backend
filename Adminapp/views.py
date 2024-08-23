from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from Users.utils import generate_pdf,send_notification_user
from Doctors.models import DoctorProfile
from Doctors.serializers import DocumentSerializer
from django.contrib import messages
from Doctors.models import Document
from.serializers import DocumentVerificationSerializer
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

logger = logging.getLogger(__name__)

class FetchDocuments(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            documents = Document.objects.select_related('doctor').all()
            print(documents)
            serializer = DocumentSerializer(documents, many=True)
            print(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching documents: {str(e)}", exc_info=True)
            return Response({'detail': 'An error occurred while fetching documents.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




import logging

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)

class VerifyDocuments(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        logger.info("Received request to verify documents.")
        
        # Check if the user is a superuser
        if not request.user.is_superuser:
            logger.warning("Unauthorized attempt to verify documents by non-superuser.")
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = DocumentVerificationSerializer(data=request.data)
        if serializer.is_valid():
            document_ids = serializer.validated_data['document_ids']
            doctor_id = serializer.validated_data['doctor_id']  # Ensure doctor_id is passed and used
            logger.debug(f"Document IDs received for verification: {document_ids}")

            try:
                # Update documents to set is_verified = True
                updated_count = Document.objects.filter(id__in=document_ids).update(is_verified=True)
                logger.info(f"Documents updated successfully: {updated_count}")

                return Response({'message': f'{updated_count} documents have been marked as verified.'}, status=status.HTTP_200_OK)

            except Exception as e:
                logger.error(f"Error updating documents: {str(e)}", exc_info=True)
                return Response({'detail': 'An error occurred while updating documents.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.warning(f"Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)