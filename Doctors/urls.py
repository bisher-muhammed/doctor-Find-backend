from django.urls import path
from.views import * 


urlpatterns = [

    
    # path('doctor/profile/', DoctorProfile_Create.as_view(), name='profile'),
    path('doctor/register/', DoctorRegisterView.as_view(), name='doctor_register'),
    path('doctor/otpverify/', OtpVerification.as_view(), name='otp_verify'),
    path('doctor/forgotpassword/', ForgotPassword.as_view(), name='forgotpassword'),
    path('doctor/change-password/<int:id>/', ChangePassword.as_view(), name='change_password'),
    path('doctor/login/', DoctorLoginView.as_view(), name='doctor_login'),
    path('doctor/resend_otp/',ResendOtpView.as_view(),name='resend_otp'),
    path('doctor/generate_slots/', GenerateSlots.as_view(), name='generate_slots'),
    path('doctor/slots/', SlotListView.as_view(), name='slots'),  # Correct endpoint
    
    path('doctor/single_slot/<int:slot_id>/', EditSlot.as_view(), name='edit-slot'),
    path('doctor/delete_slot/<int:slot_id>/', DeleteSlotView.as_view(), name='delete_slot'),

    path('doctor/edit_profile/', EditDoctorProfileView.as_view(), name='edit_profile'),
    path('doctor/doctor_details/',DoctorProfileView.as_view(),name = 'doctor_details'),
    path('doctor/<int:doctor_id>/documents/',DocumentUpload.as_view(), name='documents'),

    path('delete-expired-slots/', delete_expired_slots, name='delete_expired_slots'),
]


