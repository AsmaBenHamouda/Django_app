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
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from .utils import parse_logs


from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
import requests
from django.utils.encoding import force_bytes

from datetime import datetime, timedelta
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render
import os
from django.contrib.auth.decorators import login_required, permission_required
import base64
from cryptography.fernet import Fernet
@login_required
def admin_dashboard_view(request):
    """View for displaying the combined admin dashboard with logs, key vault, and logs filter."""
    # If you want to add any specific logic to pass context data, do it here.
    return render(request, 'admin_dashboard.html')
def encrypt_with_master_key(data):
    """Encrypt data using the master key."""
    master_key = settings.MASTER_KEY.encode()
    fernet = Fernet(master_key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_with_master_key(encrypted_data):
    """Decrypt data using the master key."""
    master_key = settings.MASTER_KEY.encode()
    fernet = Fernet(master_key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

def validate_aes_key(key, key_size):
    """Validate the AES key based on the selected key size."""
    # Check if the key length matches the required size
    if key_size == 128 and len(key) != 16:
        raise ValidationError("AES-128 key must be 16 bytes long.")
    elif key_size == 192 and len(key) != 24:
        raise ValidationError("AES-192 key must be 24 bytes long.")
    elif key_size == 256 and len(key) != 32:
        raise ValidationError("AES-256 key must be 32 bytes long.")
    
    # Optionally, check if the key is Base64 encoded (if you're using that format)
    try:
        base64.b64decode(key)
    except Exception:
        raise ValidationError("Invalid Base64 encoding for AES key.")
@login_required
@permission_required('Core.can_view_product_keys', raise_exception=True)
def manage_encryption_keys(request): 
    existing_keys = {key: settings.AES_KEYS.get(key) for key in settings.AES_KEYS}

    """View to manage encryption keys."""
    if request.method == "POST":
        # Handle form submission to update encryption keys
        key_type = request.POST.get('key_type')
        new_key = request.POST.get('new_key')
        
        if key_type and new_key:
            try:
                if key_type == 'fernet':
                    settings.FERNET_KEY = new_key.encode()
                elif key_type == 'caesar':
                    settings.AES_KEYS[key_type] = new_key  # Update Fernet key
                elif key_type.startswith('aes'):
                    # Get the AES key size from the selected encryption type (AES128, AES192, AES256)
                    key_size = int(key_type[3:])
                    # Validate the AES key before updating
                    validate_aes_key(new_key, key_size)
                    # Ensure it's AES128, AES192, or AES256 key
                    # Store the AES key (can be in Base64 or raw format)
                    settings.AES_KEYS[key_type] = new_key.encode()
                else:
                    settings.AES_KEYS[key_type] = new_key.encode()  # Store AES keys based on type
                messages.success(request, 'Key updated successfully.')
            except Exception as e:
                messages.error(request, f'Error updating key: {e}')
        
    # Fetch existing keys
    existing_keys = {
        'fernet': settings.FERNET_KEY,
        'aes128': settings.AES_KEYS.get('aes128', ''),
        'aes192': settings.AES_KEYS.get('aes192', ''),
        'aes256': settings.AES_KEYS.get('aes256', ''),
    }
    
    return render(request, 'manage_keys.html', {'existing_keys': existing_keys})

@staff_member_required  
def logs_view_admin(request):
    log_file_path = 'actions.log'  
    logs = []

    
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                logs.append(line.strip())
    except FileNotFoundError:
        logs = ["Le fichier actions.log n'existe pas."]

    
    level = request.GET.get('level', 'INFO')  
    minutes = int(request.GET.get('minutes', 60))  

    
    filtered_logs = []
    now = datetime.now()
    time_threshold = now - timedelta(minutes=minutes)

    for log in logs:
        try:
            
            parts = log.split(' ', 3)  
            log_level = parts[0]
            timestamp = parts[1] + " " + parts[2]
            log_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S,%f')

            if log_level == level and log_time >= time_threshold:
                filtered_logs.append(log)
        except (ValueError, IndexError):
            continue  

    
    context = {
        'logs': filtered_logs,
        'level': level,
        'minutes': minutes,
    }
    return render(request, 'logs_view.html', context)



logger = logging.getLogger('Core')
def check_email_view(request):
    return render(request, 'check_email.html')
def activate_user(request, uid, token):
    try:
        uid = urlsafe_base64_decode(uid).decode()
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True  
        user.save()
        return redirect('login')  
    else:
        return render(request, 'activation_failed.html')  
def send_confirmation_email(user, request):
    """
    Sends a confirmation email to the user after registration.
    """
   
    token = default_token_generator.make_token(user)
    
   
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    
    current_site = get_current_site(request)
    
   
    mail_subject = 'Activate Your Account'

    html_message = render_to_string(
        'activation_email.html',  
        {
            'user': user,
            'domain': current_site.domain,
            'uid': uid,
            'token': token,
        }
    )

    
    plain_message = f"Hello {user.first_name}!\n\nThank you for registering on our website. To complete your registration, please click the link below to activate your account:\n\nhttp://{current_site.domain}/activate/{uid}/{token}/\n\nIf you did not make this request, please ignore this email."

   
    send_mail(
        mail_subject,
        plain_message,
        settings.DEFAULT_FROM_EMAIL,  
        [user.email],
        html_message=html_message
           
    )

@login_required
def admin_logs_view(request):
    if not request.user.groups.filter(name='Admin Access').exists():
       
        messages.error(request, "You do not have permission to access this page.")
        logger.info(f"User '{request.user.username}' Try to access to Logs Page  .")
        return access_denied(request)
    logs = parse_logs() 
    logger.info(f"User '{request.user.username}'Accessed to Logs Page  .")
    return render(request, 'admin_logs.html', {'logs': logs})


@login_required
def home_view(request):
    logger.info(f"User '{request.user.username}' accessed the home page.")
    return render(request, 'invapp/home.html')
def access_denied(request):
    logger.info(f"User '{request.user.username}' accessed the to the denied page.")
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

        if password != confirm_password:
            user_data_has_error = True
            messages.error(request, "Passwords do not match")
            logger.warning(f"Registration failed: Passwords do not match for username '{username}'.")

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
            send_confirmation_email(new_user, request)
            return redirect('check_email')

    return render(request, 'register.html')

def LoginView(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        recaptcha_response = request.POST.get('g-recaptcha-response')  

        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        recaptcha_secret_key = settings.RECAPTCHA_PRIVATE_KEY 

        data = {
            'secret': recaptcha_secret_key,
            'response': recaptcha_response
        }
        recaptcha_result = requests.post(recaptcha_url, data=data)
        result_json = recaptcha_result.json()

        
        if result_json.get('success'):
            
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
            logger.info(f"User '{request.user.username}' try to reset his password.")

            email_message = EmailMessage(
                'Reset your password', 
                email_body,
                settings.EMAIL_HOST_USER, 
                [email] 
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
                logger.warning("Password reset failed due to form errors.")
                return redirect('reset-password', reset_id=reset_id)

    
    except PasswordReset.DoesNotExist:
        
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
            product = form.save(commit=False)  
            product.created_by = request.user  
            product.save()
            logger.info("Product created successfully.")
    
            return redirect('product_list')  
        else:
            logger.warning("Invalid form data for product creation.")
    else:
        form = ProductForm()
    return render(request, 'invapp/product_form.html', {
        'form': form,
        'username': request.user.username  
    })
# Read View
def product_list_view(request):
    logger.info("Accessed product list view.")
    can_view_all_products = request.user.has_perm('Core.can_view_all_products')
    if can_view_all_products:
        products = Product.objects.all()
    else:
        products = Product.objects.filter(created_by=request.user)

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
