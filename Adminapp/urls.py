from django.urls import path
from .views import *
from Adminapp.views import VerifyDocuments



urlpatterns = [

    path('admin/login/',AdminLogin.as_view(),name='admin_login'),
    path('admin/fetch_documents/',FetchDocuments.as_view(),name='fetch_documents'),
    # In urls.py
    path('admin/verify_documents/', VerifyDocuments.as_view(), name='verify_documents')


    

]
