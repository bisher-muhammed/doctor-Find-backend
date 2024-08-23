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

    
]

