from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from .serializers import UserSerializer
from django.contrib.auth.models import User

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data

        # Ensure all required fields are present
        required_fields = ['first_name', 'last_name', 'email', 'phone_number', 'password']
        if not all(field in data for field in required_fields):
            return Response({'detail': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = self.perform_create(serializer)
            user_serializer = UserSerializer(user)
            return Response({'detail': 'User registered successfully', 'user': user_serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def perform_create(self, serializer):
        return serializer.save()


    
class RetrieveUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)




