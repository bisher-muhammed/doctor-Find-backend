import random
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserRegisterSerializer, UserSerializer, OtpVerificationSerializer,UserLoginSerializer
from .models import UserProfile  # Ensure UserProfile is imported
from .utils import send_otp_via_email
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        print("Login attempts:", request.data)

        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')

            print(f"Validating user with email:", email)

            user = authenticate(username=email, password=password)  # Ensure the username is correctly mapped to email
            print('Authenticated user:', user)

            if user is None:
                print("Authentication failed: Invalid credentials")
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

            elif not user.is_active:
                print("User account is blocked")
                return Response({'error': 'Blocked'}, status=status.HTTP_403_FORBIDDEN)

            else:
                if not user.is_staff:
                    print("User is not staff; processing tokens")
                    UserProfile.objects.get_or_create(user=user)
                    refresh = RefreshToken.for_user(user)
                    refresh['username'] = str(user.username)

                    access_token = str(refresh.access_token)
                    refresh_token = str(refresh)

                    content = {
                        'userid': user.id,
                        'access_token': access_token,
                        'refresh_token': refresh_token,
                        'isAdmin': user.is_superuser,
                    }
                    print("Login successful. Tokens generated.")
                    return Response(content, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'This account is not a user account'}, status=status.HTTP_401_UNAUTHORIZED)
                
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        required_fields = ['username', 'email', 'phone_number', 'password']
        if not all(field in data for field in required_fields):
            return Response({'detail': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserRegisterSerializer(data=data)
        if serializer.is_valid():
            try:
                user = User(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data['email'],
                    phone_number=serializer.validated_data['phone_number']
                )
                user.set_password(serializer.validated_data['password'])
                user.is_active = False
                otp = str(random.randint(1000, 9999))
                user.otp = otp
                user.save()
                UserProfile.objects.get_or_create(user=user)
                send_otp_via_email(user.email, otp)

                response_data = {
                    'message': 'OTP sent successfully.',
                    'email': user.email
                }
                return Response(response_data, status=status.HTTP_200_OK)
            except Exception as e:
                print(f"Error during user registration: {e}")
                return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            print(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Otpverification(APIView):
    def post(self, request):
        serializer = OtpVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                email = serializer.validated_data.get('email')
                entered_otp = serializer.validated_data.get('otp')
                user = User.objects.get(email=email)

                if user.otp == entered_otp:
                    user.is_active = True
                    user.otp = None
                    user.save()
                    return Response({'message': 'User registered and verified successfully'}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'error': 'User not found or already verified'}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                print(f"Error during OTP verification: {e}")
                return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        


class ForgotPassword(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self,request,*args,**kwargs):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            send_otp_via_email(user.email,user.otp)
            response_data = {
                'message': 'OTP sent successfully',
                'email': user.email,
                'user_id': user.id,
            }
            return Response(response_data,status=status.HTTP_200_ok)
        except User.DoesNotExist:
            return Response({'exists':False,'message':'Invalid Email'},status=status.HTTP_404_NOT_FOUND)


class ChangePassword(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self,request,*args, **kwargs):
        user_id = self.kwargs.get('id')
        print(user_id)
        new_password = request.data.get('password')
        
        
        
        try:
            user = User.objects.get(id=user_id)
            user_password = make_password(new_password)
            user.password = user_password
            user.save()

            return Response({'success':True,'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error':'User not found'},status=status.HTTP_404_NOT_FOUND)
    



                



   


    





