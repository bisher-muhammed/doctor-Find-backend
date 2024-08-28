from django.contrib import admin
from .models import MyUser,UserProfile
from Doctors.models import Slots,Document,DoctorProfile,Bookings

admin.site.register(MyUser)
admin.site.register(UserProfile)
admin.site.register(Slots)
admin.site.register(Document)
admin.site.register(DoctorProfile)
admin.site.register(Bookings)