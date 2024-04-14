from django.http import JsonResponse

from auth_api.models import CustomUser
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.hashers import make_password, check_password
from django.core import serializers
from django.http import JsonResponse
from django.contrib.auth.hashers import check_password
import json
# from .models import CustomUser

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

@csrf_exempt
def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']
        private_key, public_key = generate_key_pair()

        user = CustomUser.objects.create_user(username=username, password=password, email=email)
        user.private_key = private_key
        user.public_key = public_key
        user.save()

        return JsonResponse({'message': 'Signup successful'})

@csrf_exempt

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        try:
            user = CustomUser.objects.get(username=username)
            if check_password(password, user.password):
                request.session.set_expiry(0)
                request.session.save()
                request.session['user_id'] = user.id

                private_key, public_key = user.private_key, user.public_key
                return JsonResponse({'private_key': private_key, 'public_key': public_key})
        except CustomUser.DoesNotExist:
            pass

        return JsonResponse({'error': 'Invalid username or password'}, status=401)
    