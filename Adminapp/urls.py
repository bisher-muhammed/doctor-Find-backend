from django.urls import path
from .views import *
urlpatterns = [

    path('admin/login/',AdminLogin.as_view(),name='admin_login'),
    path('admin/fetch_documents/',FetchDocuments.as_view(),name='fetch_documents'),
    path('admin/verifiy_documents/',VerifyDocuments.as_view(),name='verifyDocuments')

    

]
