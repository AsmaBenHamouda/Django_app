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
import logging
import logging
from django.core.exceptions import PermissionDenied


logger = logging.getLogger('Core')



@login_required
def home_view(request):
    logger.info(f"User '{request.user.username}' accessed the home page.")
    return render(request, 'invapp/home.html')
def access_denied(request):
    return render(request, 'access_denied.html')
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
            logger.warning(f"Registration failed: Username '{username}' already exists.")

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")
            logger.warning(f"Registration failed: Email '{email}' already exists.")

        if len(password) < 5:
            user_data_has_error = True
            messages.error(request, "Password must be at least 5 characters")

        # Check if passwords match
        if password != confirm_password:
            user_data_has_error = True
            messages.error(request, "Passwords do not match")
            logger.warning(f"Registration failed: Passwords do not match for username '{username}'.")

        # Validate password strength
        try:
            validate_password(password)
        except ValidationError as e:
            user_data_has_error = True
            for error in e.messages:
                messages.error(request, error)
            logger.warning(f"Registration failed: Password validation failed for username '{username}'.")

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
            logger.info(f"New user registered: Username '{username}', Email '{email}'.")
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
                logger.info(f"User '{username}' successfully logged in.")
                return redirect('home')
            else:
                logger.warning(f"Login failed: Invalid credentials for username '{username}'.")
                messages.error(request, "Invalid login credentials")
                return redirect('login')
        else:
            messages.error(request, "reCAPTCHA verification failed. Please try again.")
            logger.warning(f"Login failed: reCAPTCHA verification failed for username '{username}'.")
            return redirect('login')

    return render(request, 'login.html')


def LogoutView(request):
    logger.info(f"User '{request.user.username}' logged out.")
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

            logger.info(f"Password reset email sent to '{email}'.")
            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            logger.warning(f"Password reset failed: No user with email '{email}' found.")
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')

    return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):
    logger.info(f"Password reset attempt with reset_id: {reset_id}")

    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        # redirect to forgot password page if code does not exist
        logger.warning("Invalid reset_id. Redirecting to forgot-password.")
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):
    logger.info(f"Attempting password reset with reset_id: {reset_id}")
    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)
        logger.info(f"Found password reset entry for reset_id: {reset_id}")
        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            logger.debug("Processing password reset form data.")
            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match')
                logger.warning("Passwords do not match.")

            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, 'Password must be at least 5 characters long')

            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Reset link has expired')
                logger.error("Reset link has expired.")

                password_reset_id.delete()

            if not passwords_have_error:
                user = password_reset_id.user
                user.set_password(password)
                user.save()

                password_reset_id.delete()
                logger.info("Password reset successfully. Redirecting to login.")

                messages.success(request, 'Password reset. Proceed to login')
                return redirect('login')
            else:
                # redirect back to password reset page and display errors
                logger.warning("Password reset failed due to form errors.")
                return redirect('reset-password', reset_id=reset_id)

    
    except PasswordReset.DoesNotExist:
        
        # redirect to forgot password page if code does not exist
        logger.error(f"PasswordReset with reset_id: {reset_id} does not exist.")
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

    return render(request, 'reset_password.html')
# Create View
def product_create_view(request):
    if not request.user.has_perm('Core.can_create_product'):
        return access_denied(request)
    
    logger.info("Accessed product creation view.")
    if request.method == "POST":
        form = ProductForm(request.POST)
        if form.is_valid():
            form.save()
            logger.info("Product created successfully.")
    
            return redirect('product_list')  # Redirect to the product list view
        else:
            logger.warning("Invalid form data for product creation.")
    else:
        form = ProductForm()
    return render(request, "invapp/product_form.html", {"form": form})
# Read View
def product_list_view(request):
    logger.info("Accessed product list view.")
    can_view_all_products = request.user.has_perm('Core.can_view_all_products')
    if can_view_all_products:
        products = Product.objects.all()
    else:
        products = Product.objects.filter(created_by=request.user)

    # Pass the permission and products to the template
    return render(request, 'invapp/product_list.html', {
        'products': products,
        'can_view_all_products': can_view_all_products
    })
# Update View
def product_update_view(request, product_id):
    if not request.user.has_perm('Core.can_update_product'):
        return access_denied(request)
    logger.info(f"Accessed product update view for product_id: {product_id}.")
    product = Product.objects.get(product_id=product_id)
    form = ProductForm(instance=product)

    if request.method == "POST":
        form = ProductForm(request.POST, instance=product)
        if form.is_valid():
            form.save()
            logger.info(f"Product with product_id: {product_id} updated successfully.")
            return redirect('product_list')
        else:
            logger.warning(f"Invalid form data for product update, product_id: {product_id}")


    # Decrypt bank_number if it exists for display in the form
    if product.bank_number:
        decrypted_bank_number = product.display_encrypted_bank_number()
        form.fields['bank_number'].initial = decrypted_bank_number
        logger.debug(f"Decrypted bank number for product_id: {product_id}.")

    return render(request, 'invapp/product_form.html', {'form': form})
# Delete View
def product_delete_view(request, product_id):
    if not request.user.has_perm('myapp.can_delete_product'):
        return access_denied(request)
    logger.info(f"Accessed product delete view for product_id: {product_id}.")
    product = Product.objects.get(product_id = product_id)
    if request.method == 'POST':
        product.delete()
        logger.info(f"Product with product_id: {product_id} deleted successfully.")
        return redirect('product_list')
    return render(request, 'invapp/product_confirm_delete.html', {'product':product})
