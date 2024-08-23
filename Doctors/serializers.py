from datetime import timedelta,datetime
from venv import logger
from django.utils import timezone
from flask import Response
from grpclib import Status
from rest_framework import serializers,viewsets
from Users.models import MyUser  # Assuming this is the custom user model
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import DoctorProfile, Slots,Document

class DoctorRegisterSerializer(serializers.ModelSerializer):
    user_type = serializers.ChoiceField(choices=MyUser.USER_TYPE_CHOICES, default='doctor')

    class Meta:
        model = MyUser
        fields = ['id', 'username', 'email', 'phone_number', 'password', 'user_type']
        extra_kwargs = {
            'password': {'write_only': True},
            'user_type': {'read_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        validated_data['user_type'] = 'doctor'
        instance = self.Meta.model(**validated_data)

        if password is not None:
            instance.set_password(password)
        else:
            raise serializers.ValidationError({"password": "Password is required."})

        
        return instance


class DoctorLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        print("Validating data:", data)

        if not email or not password:
            raise serializers.ValidationError("Email and password are required")
        
        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError('Invalid credentials')

        if not user.is_active:
            raise serializers.ValidationError('Account is blocked')

        print("User validated successfully.")
        return {
            'user': user,
            'email': email,
            'password': password,
        }


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        return token


class OtpVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)




        






from rest_framework import serializers
from .models import DoctorProfile, Document

class DocumentSerializer(serializers.ModelSerializer):
    doctor_username = serializers.CharField(source='doctor.user.username', read_only=True)
    doctor_specification = serializers.CharField(source='doctor.specification', read_only=True)
    doctor_id = serializers.IntegerField(source='doctor.doctor_id',read_only=True)

    class Meta:
        model = Document
        fields = ['id', 'file', 'uploaded_at', 'doctor_username', 'doctor_specification','doctor_id']

class DoctorProfileSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()
    documents = DocumentSerializer(many=True, read_only=True)  # Assuming documents are read-only in this context

    class Meta:
        model = DoctorProfile
        fields = [
            'username', 'email', 'phone_number',
            'id', 'first_name', 'last_name', 'specification',
            'bio', 'experience', 'available_from', 'available_to',
            'is_verified',
            'profile_pic',
            'documents'
        ]

    def get_username(self, obj):
        return obj.user.username

    def get_email(self, obj):
        return obj.user.email

    def get_phone_number(self, obj):
        return obj.user.phone_number

    def validate(self, data):
        required_fields = ['first_name', 'last_name', 'specification', 'bio', 'experience', 'available_from', 'available_to']
        for field in required_fields:
            if field not in data or not data.get(field):
                raise serializers.ValidationError({field: "This field is required."})

        if 'experience' in data:
            if not isinstance(data['experience'], int):
                raise serializers.ValidationError({'experience': 'Experience must be an integer.'})
            if data['experience'] < 0:
                raise serializers.ValidationError({'experience': 'Experience must be a positive integer.'})

        return data

    def create(self, validated_data):
        user = self.context['request'].user
        doctor_profile, created = DoctorProfile.objects.get_or_create(user=user, defaults=validated_data)
        if not created:
            for attr, value in validated_data.items():
                setattr(doctor_profile, attr, value)
            doctor_profile.save()
        return doctor_profile

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance



######################################################################################################################
class SlotSerializer(serializers.ModelSerializer):
    class Meta:
        model = Slots
        fields = ['id','start_time', 'end_time', 'duration', 'end_date']

class SlotViewSet(viewsets.ModelViewSet):
    queryset = Slots.objects.all()
    serializer_class = SlotSerializer

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=Status.HTTP_400_BAD_REQUEST)

class SlotViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Slots.objects.all()
    serializer_class = SlotSerializer

    def get_queryset(self):
        doctor_id = self.request.query_params.get('doctor_id')
        start_date_str = self.request.query_params.get('start_date')
        end_date_str = self.request.query_params.get('end_date')

        # Initial queryset for unblocked slots
        queryset = self.queryset.filter(is_blocked=False)

        # Filter by doctor_id if provided
        if doctor_id:
            queryset = queryset.filter(doctor_id=doctor_id)

        # Filter by date range if provided
        if start_date_str and end_date_str:
            try:
                start_date = timezone.make_aware(datetime.strptime(start_date_str, "%Y-%m-%d"))
                end_date = timezone.make_aware(datetime.strptime(end_date_str, "%Y-%m-%d"))
                queryset = queryset.filter(start_time__date__range=[start_date, end_date])
            except ValueError:
                logger.error("Invalid date format provided")

        return queryset.distinct()


from django.middleware.csrf import CsrfViewMiddleware
from rest_framework.exceptions import ValidationError

class SlotDeleteSerializer(serializers.Serializer):
    slot_id = serializers.IntegerField()

    def validate(self, attrs):
        request = self.context['request']
        self._validate_csrf(request)
        return super().validate(attrs)

    def validate_slot_id(self, value):
        """
        Validate that the slot exists and is associated with the current user.
        """
        from .models import Slots  # Import here to avoid circular import issues
        user = self.context['request'].user

        try:
            slot = Slots.objects.get(id=value, user=user)
        except Slots.DoesNotExist:
            raise serializers.ValidationError('Slot not found or not associated with the current user.')

        return value

    def _validate_csrf(self, request):
        """
        Validates the CSRF token.
        """
        try:
            csrf_middleware = CsrfViewMiddleware()
            csrf_middleware.process_view(request, None, (), {})
        except ValidationError as e:
            raise serializers.ValidationError('CSRF token missing or incorrect.')





