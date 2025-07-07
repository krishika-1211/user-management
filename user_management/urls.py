from django.urls import path

from user_management import views

urlpatterns = [
    path("login/", views.LoginAPI.as_view(), name="login"),
    path("signup/", views.SignupAPI.as_view(), name="signup"),
    path("user/", views.BasicCRUD.as_view(), name="user"),
    path("admin/", views.AdminPrev.as_view(), name="get_admin"),
    path("admin/<int:user_id>", views.AdminPrev.as_view(), name="admin"),
    path("forgot-password/", views.ForgotPassword.as_view(), name="forgot_password"),
    path("reset-password/", views.ResetPassword.as_view(), name="reset_password"),
]
