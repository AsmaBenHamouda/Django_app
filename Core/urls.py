from django.urls import path 
from . import views
from .views import admin_logs_view
from .views import logs_view_admin
from .views import manage_encryption_keys
from .views import admin_dashboard_view


urlpatterns = [
    path('', views.home_view, name='home'),
    path('register/', views.RegisterView, name='register'),
    path('login/', views.LoginView, name='login'),
    path('logout/', views.LogoutView, name='logout'),
    path('forgot-password/', views.ForgotPassword, name='forgot-password'),
    path('password-reset-sent/<str:reset_id>/', views.PasswordResetSent, name='password-reset-sent'),
    path('reset-password/<str:reset_id>/', views.ResetPassword, name='reset-password'),
    path('create/', views.product_create_view, name="product_create"),
    path('list/', views.product_list_view, name="product_list"),
    path('update/<int:product_id>/', views.product_update_view, name="product_update"),
    path('delete/<int:product_id>/', views.product_delete_view, name="product_delete"),
    path('logs/', admin_logs_view, name='admin_logs'),
    path('logsfiltrer/', logs_view_admin, name='logs_view'),  
    path('activate/<str:uid>/<str:token>/', views.activate_user, name='activate_user'),
    path('check_email/', views.check_email_view, name='check_email'),  # Add this line
    path('manage-keys/', manage_encryption_keys, name='manage_keys'),  # Add this line
    path('admin-dashboard/', admin_dashboard_view, name='admin_dashboard'),

  

    
]