import json
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from auth_api.models import CustomUser
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from cryptography.hazmat.primitives import serialization
from django.utils.http import urlsafe_base64_encode
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.hashers import make_password, check_password
from django.core import serializers
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import EmailMessage, BadHeaderError
from django.conf import settings
from django.core.mail import send_mail
import secrets
import string
from django.utils import timezone
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password

VERIFICATION_CODE_EXPIRATION_MINUTES = 5

User = get_user_model()



def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_hex = "0x" + pem_private_key.hex()
    public_key_hex = "0x" + pem_public_key.hex()

    return private_key_hex, public_key_hex

def generate_verification_code(length=6):
    characters = string.digits  
    verification_code = ''.join(secrets.choice(characters) for _ in range(length))
    return verification_code


@csrf_exempt
def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']
        private_key, public_key = generate_key_pair()

        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({'error': 'Invalid email'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)
       
        try:
            user = CustomUser.objects.create_user(username=username, password=password, email=email)
            user.private_key = private_key
            user.public_key = public_key
            # Send verification email
            verification_code=send_verification_email(user)
            user.verification_code=verification_code
            if user.is_active:
             user.save()
        except BadHeaderError:
            return JsonResponse({'error': 'Invalid header found in email.'}, status=400)

        return JsonResponse({'success': 'User registered successfully. Please check your email for verification.'}, status=201)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

def send_verification_email(user):
    if user.is_active:
        return  # Do not send verification email if already verified

    verification_code = generate_verification_code()
    user.verification_code = verification_code
    user.verification_code_created = timezone.now()  # Store the timestamp of code creation
    user.save()

    expiration_time = user.verification_code_created + timezone.timedelta(minutes=VERIFICATION_CODE_EXPIRATION_MINUTES)
    expiration_minutes = VERIFICATION_CODE_EXPIRATION_MINUTES

    mail_subject = 'Activate your account'
    message = f'Your verification code is: {verification_code}\n'

    email = user.email
    recipient_list = [email]
    send_mail(mail_subject, message, settings.EMAIL_HOST_USER, recipient_list, fail_silently=True)

    return verification_code

@csrf_exempt
def verify_email(request):
    if request.method == 'POST':
        verification_code = request.POST['verification_code']

        try:
            user = CustomUser.objects.get(verification_code=verification_code)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'Invalid verification code'}, status=400)

        user.is_active = True
        user.save()

        return JsonResponse({'success': 'Email verified successfully'}, status=200)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


    
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        try:
            user = CustomUser.objects.get(username=username)
            if check_password(password, user.password):
               
                if user.is_active:
                    request.session.set_expiry(0)
                    request.session.save()
                    request.session['id'] = user.id

                    private_key, public_key = user.private_key, user.public_key
                    return JsonResponse({'private_key': private_key, 'public_key': public_key})
                else:
                    return JsonResponse({'error': 'Email not confirmed'}, status=401)
        except CustomUser.DoesNotExist:
            pass

        return JsonResponse({'error': 'Invalid username or password'}, status=401)
