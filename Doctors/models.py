from django.db import models
from Users.models import MyUser
from django.utils import timezone
from datetime import timedelta


class DoctorProfile(models.Model):
    user = models.OneToOneField(MyUser,on_delete=models.CASCADE)
    first_name = models.CharField(max_length=10, null=True,blank =True)
    last_name = models.CharField(max_length=10, null= True,blank=True)
    specification = models.CharField(max_length=100,null=True,blank= True)
    bio = models.TextField()
    experience = models.IntegerField(default=0)
    available_from = models.TimeField(null=True, default=None)
    available_to = models.TimeField(null=True, default=None)
    profile_pic = models.ImageField(upload_to='media/doctor/profile_pic', blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    


    def __str__(self):
        return f"{self.user.username}"
    


class Slots(models.Model):
    doctor = models.ForeignKey('DoctorProfile', on_delete=models.CASCADE, related_name='slots')
    start_time = models.DateTimeField()
    start_date = models.DateField()
    end_time = models.DateTimeField()
    duration = models.PositiveIntegerField()  # Add duration field here
    is_blocked = models.BooleanField(default=False)
    
    end_date = models.DateField()

    def save(self, *args, **kwargs):
        # Convert duration to hours if it's 60 minutes or more
        if self.duration >= 60:
            self.duration = timedelta(minutes=self.duration).total_seconds() / 3600  # Convert to hours

        super(Slots, self).save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.doctor.user.username}: {self.start_time.strftime('%I:%M %p')} - {self.end_time.strftime('%I:%M %p')}"
    


class Document(models.Model):
    doctor = models.ForeignKey(DoctorProfile,related_name='doctors',on_delete=models.CASCADE)
    file = models.FileField(upload_to='media/doctor/documents')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    

    def __str__(self):
        return f"{self.file.name} uploaded by {self.doctor.user.username}"

