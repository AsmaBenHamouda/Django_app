from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import requests
from .forms import ProductForm
from .models import Product

@login_required
def home_view(request):
    return render(request, 'invapp/home.html')
def RegisterView(request):

    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password') 
        

        user_data_has_error = False

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, "Username already exists")

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")

        if len(password) < 5:
            user_data_has_error = True
            messages.error(request, "Password must be at least 5 characters")

        # Check if passwords match
        if password != confirm_password:
            user_data_has_error = True
            messages.error(request, "Passwords do not match")

        # Validate password strength
        try:
            validate_password(password)
        except ValidationError as e:
            user_data_has_error = True
            for error in e.messages:
                messages.error(request, error)

        if user_data_has_error:
            return redirect('register')
        else:
            new_user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email, 
                username=username,
                password=password
            )
            messages.success(request, "Account created. Login now")
            return redirect('login')

    return render(request, 'register.html')

def LoginView(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        recaptcha_response = request.POST.get('g-recaptcha-response')  # Get the reCAPTCHA response

        # Verify reCAPTCHA with Google
        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        recaptcha_secret_key = settings.RECAPTCHA_PRIVATE_KEY  # Add the secret key from settings.py

        data = {
            'secret': recaptcha_secret_key,
            'response': recaptcha_response
        }
        recaptcha_result = requests.post(recaptcha_url, data=data)
        result_json = recaptcha_result.json()

        # Check if reCAPTCHA was successfully verified
        if result_json.get('success'):
            # Authenticate user if reCAPTCHA is valid
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')
            else:
                messages.error(request, "Invalid login credentials")
                return redirect('login')
        else:
            messages.error(request, "reCAPTCHA verification failed. Please try again.")
            return redirect('login')

    return render(request, 'login.html')


def LogoutView(request):

    logout(request)

    return redirect('login')
def ForgotPassword(request):

    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})

            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            email_body = f'Reset your password using the link below:\n\n\n{full_password_reset_url}'
        
            email_message = EmailMessage(
                'Reset your password', # email subject
                email_body,
                settings.EMAIL_HOST_USER, # email sender
                [email] # email  receiver 
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')

    return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):

    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):

    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match')

            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, 'Password must be at least 5 characters long')

            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Reset link has expired')

                password_reset_id.delete()

            if not passwords_have_error:
                user = password_reset_id.user
                user.set_password(password)
                user.save()

                password_reset_id.delete()

                messages.success(request, 'Password reset. Proceed to login')
                return redirect('login')
            else:
                # redirect back to password reset page and display errors
                return redirect('reset-password', reset_id=reset_id)

    
    except PasswordReset.DoesNotExist:
        
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

    return render(request, 'reset_password.html')
# Create View
def product_create_view(request):
    if request.method == "POST":
        form = ProductForm(request.POST)
        if form.is_valid():
            form.save()  # Save the instance to the database
            return redirect('product_list')  # Redirect to the product list view
    else:
        form = ProductForm()
    return render(request, "invapp/product_form.html", {"form": form})
# Read View
def product_list_view(request):
    products = Product.objects.all()
    return render(request, 'invapp/product_list.html', {'products':products})

# Update View
def product_update_view(request, product_id):
    product = Product.objects.get(product_id=product_id)
    form = ProductForm(instance=product)

    if request.method == "POST":
        form = ProductForm(request.POST, instance=product)
        if form.is_valid():
            form.save()
            return redirect('product_list')

    # Decrypt bank_number if it exists for display in the form
    if product.bank_number:
        decrypted_bank_number = product.decrypt_bank_number()
        form.fields['bank_number'].initial = decrypted_bank_number

    return render(request, 'invapp/product_form.html', {'form': form})
# Delete View
def product_delete_view(request, product_id):
    product = Product.objects.get(product_id = product_id)
    if request.method == 'POST':
        product.delete()
        return redirect('product_list')
    return render(request, 'invapp/product_confirm_delete.html', {'product':product})
