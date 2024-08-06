from django.urls import path
from .views import *

urlpatterns = [
    path('signup/', RegisterView.as_view(), name='signup'),

    path ('login/',LoginView.as_view(), name ='login'),
    path('otpverify/',Otpverification.as_view(),name="otp_verify")

    
]
