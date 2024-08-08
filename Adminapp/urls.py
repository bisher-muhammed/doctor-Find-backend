from django.urls import path
from .views import *
urlpatterns = [

    path('admin/login/',AdminLogin.as_view(),name='admin_login')
    

]
