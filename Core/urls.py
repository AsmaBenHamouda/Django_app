from django.urls import path
from . import views

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

    
]