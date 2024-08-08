from django.urls import path
from .views import *

urlpatterns = [
    path('signup/', RegisterView.as_view(), name='signup'),

    path ('login/',LoginView.as_view(), name ='login'),
    path('otpverify/',Otpverification.as_view(),name="otp_verify"),
    path ('changepassword/<int:id>/',ChangePassword.as_view(),name='change_password'),
    path('fpassword/',ForgotPassword.as_view(),name='fpassword')

    
]
