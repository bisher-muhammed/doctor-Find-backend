# utils.py

from django.core.mail import send_mail
from django.conf import settings 
import random 
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth import get_user_model

User = get_user_model()

def send_otp_via_email(email, otp):
    subject = "Welcome to Find Doctor! - User Verification Mail"
    context = {'otp': otp}
    html_content = render_to_string('email.html', context)
    text_content = strip_tags(html_content)
    email_from = settings.EMAIL_HOST_USER
    try:
        msg = EmailMultiAlternatives(subject, text_content, email_from, [email])
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        user_obj = User.objects.get(email=email)
        user_obj.otp = otp
        user_obj.save()
        print(f"OTP sent successfully to {email}")
        print(otp)
    except Exception as e:
        print(f"Error sending OTP to {email}: {e}")

def send_approval(email):
    subject = "Find Doctor! Request Approved"
    html_content = render_to_string('doctor_approval.html')
    text_content = strip_tags(html_content)
    email_from = settings.EMAIL_HOST_USER
    try:
        msg = EmailMultiAlternatives(subject, text_content, email_from, [email])
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        print(f"Approval sent successfully to {email}")
    except Exception as e:
        print(f"Error sending approval to {email}: {e}")
