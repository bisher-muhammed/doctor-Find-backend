
import random
from django.utils import timezone
from datetime import timedelta
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from rest_framework.generics import ListAPIView,CreateAPIView
from Doctors.serializers import DoctorProfileSerializer,SlotCreateSerializer




from Doctors.models import DoctorProfile,Slots,Bookings
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
                user.otp_expiry = timezone.now()+timedelta(minutes=1)

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

                if user.otp == entered_otp and user.otp_expiry > timezone.now():
                    user.is_active = True
                    user.otp = None
                    user.otp_expiry = None
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

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            otp = str(random.randint(1000, 9999))
            print("Generated OTP:", otp)
            # Set OTP expiry time (e.g., 10 minutes from now)
            otp_expiry = timezone.now() + timedelta(minutes=10)
            send_otp_via_email(user.email, otp)
            user.otp = otp
            user.otp_expiry = otp_expiry
            user.save()

            response_data = {
                'message': 'OTP sent successfully',
                'email': user.email,
                'user_id': user.id,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'exists': False, 'message': 'Invalid Email'}, status=status.HTTP_404_NOT_FOUND)


class ChangePassword(APIView):
    
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
    


class ResendOtpView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            if user.is_active:
                return Response({'error': 'User is already verified'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate a new OTP and set expiry
            otp = str(random.randint(1000, 9999))
            user.otp = otp
            user.otp_expiry = timezone.now() + timedelta(minutes=1)  # OTP valid for 5 minutes
            user.save()

            # Send OTP to the user's email
            send_otp_via_email(user.email, otp)
            print("otp re_sended",otp)

            return Response({'message': 'OTP resent successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error during OTP resend: {e}")
            return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


                
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "UserProfile not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Use a serializer that includes profile details
        serializer = UserProfileDetailSerializer(user_profile)
        return Response(serializer.data)

class EditProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({'error': "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserProfileSerializer(user_profile)
        return Response(serializer.data)


    def put(self, request):
            try:
                user_profile = UserProfile.objects.get(user=request.user)
            except UserProfile.DoesNotExist:
                return Response({'error': "UserProfile does not exist"}, status=status.HTTP_404_NOT_FOUND)

            serializer = UserProfileSerializer(user_profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            print("error",serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

#######################################################################################################################################################

class Doctors_list(ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    serializer_class = DoctorProfileSerializer

    def get_queryset(self):
        # This method should return the queryset for the view
        queryset = DoctorProfile.objects.filter(is_verified=True)
        
        return queryset

    def get(self, request, *args, **kwargs):
        # This method handles GET requests
        queryset = self.get_queryset()
        
        
        serializer = self.get_serializer(queryset, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)


class SlotListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SlotCreateSerializer

    def get_queryset(self):
        doctor_id = self.kwargs.get('doctor_id')
        print(f"Requested doctor ID: {doctor_id}")

        try:
            doctor = DoctorProfile.objects.get(id=doctor_id)
            if doctor.is_verified:
                slots = Slots.objects.filter(doctor=doctor,is_booked = False)
                
                return slots
            else:
                return Slots.objects.none()
        except DoctorProfile.DoesNotExist:
            return Slots.objects.none()
        
    def get(self, request, *args, **kwargs):
        doctor_id = self.kwargs.get('doctor_id')

        try:
            doctor = DoctorProfile.objects.get(id=doctor_id)
        except DoctorProfile.DoesNotExist:
            return Response({'detail': 'Doctor not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the doctor is verified
        if not doctor.is_verified:
            return Response({'detail': 'Doctor is not verified.'}, status=status.HTTP_404_NOT_FOUND)

        # Fetch the slots for the doctor
        slots = self.get_queryset()

        # Serialize the doctor profile
        doctor_serializer = DoctorProfileSerializer(doctor)
        print(f"Doctor Profile Serialized Data: {doctor_serializer.data}")

        # Serialize the slots
        slot_serializer = self.get_serializer(slots, many=True)
        

        # Combine the data
        response_data = {
            'doctor': doctor_serializer.data,
            'slots': slot_serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)


        
    
class BookSlotView(CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BookingSerializer

    def post(self, request, doctor_id, slot_id):
        try:
            # Retrieve the doctor and slot based on the provided IDs
            doctor = DoctorProfile.objects.get(id=doctor_id)
            slot = Slots.objects.get(id=slot_id, doctor=doctor, is_booked=False)

            # Check if the slot is already booked (redundant since you're filtering by is_booked=False)
            if slot.is_booked:
                return Response({"error": "This slot is already booked."}, status=status.HTTP_400_BAD_REQUEST)

            # Create a new booking instance with the correct field name
            booking = Bookings.objects.create(user=request.user, doctor=doctor, slots=slot)
            
            # Mark the slot as booked
            slot.is_booked = True
            slot.save()

            # Serialize the booking data
            serializer = BookingSerializer(booking)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except DoctorProfile.DoesNotExist:
            return Response({"error": "Doctor not found."}, status=status.HTTP_404_NOT_FOUND)
        except Slots.DoesNotExist:
            return Response({"error": "Slot not found or already booked."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_queryset(self):
        # Return an empty queryset as it's not needed in this view
        return Bookings.objects.none()


class MyAppointments(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BookingSerializer
    def get_queryset(self):
        user = self.request.user
        return Bookings.objects.filter(user=user)
    

        
    

        
        
        