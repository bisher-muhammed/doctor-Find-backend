from django.urls import path
from .views import *
from.views import ResendOtpView


urlpatterns = [
    path('resend_otp/', ResendOtpView.as_view(), name='resend_otp'),
    path('signup/', RegisterView.as_view(), name='signup'),

    path ('login/',LoginView.as_view(), name ='login'),
    path('otpverify/',Otpverification.as_view(),name="otp_verify"),
    path ('changePassword/<int:id>/',ChangePassword.as_view(),name='changePassword'),
    path('fpassword/',ForgotPassword.as_view(),name='fpassword'),
    path('user_details/',UserProfileView.as_view(),name='user_detials'),
    path('edit_profile/', EditProfileView.as_view(), name='edit_profile'),
    path('doctors_list/',Doctors_list.as_view(),name='doctors_list'),
    path('available_slots/<int:doctor_id>/', SlotListView.as_view(), name='available_slots'),
    
    path('book-slot/<int:doctor_id>/<int:slot_id>/', BookSlotView.as_view(), name='book_slot'),
    path('my-appointments/', MyAppointments.as_view(), name='my_appointments'),



    
]

