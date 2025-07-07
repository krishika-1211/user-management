from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.timezone import now
from django.conf import settings

import os
from dotenv import load_dotenv

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication

from user_management.serializers import (
    LoginSerializer,
    SignupSerializer,
    UserSerializer,
    UpdateUserSerializer,
    AdminUpdateSerializer,
    ResetRequestserializer,
)
from user_management.models import CustomUser
from user_management.utils import SmtpMail

load_dotenv()

# Create your views here.


class LoginAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        serializer = LoginSerializer(data=data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.get(email=serializer.data["email"])
        if user is None:
            return Response(
                {"message": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )

        user.last_login = now()
        user.save(update_fields=["last_login"])

        refresh = RefreshToken.for_user((user))
        access_token = str(refresh.access_token)

        return Response(
            {
                "message": "login successful",
                "refresh": str(refresh),
                "access token": access_token,
            },
            status=status.HTTP_200_OK,
        )


class SignupAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        serializer = SignupSerializer(data=data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()

        return Response(
            {"message": "User created successfully"}, status=status.HTTP_201_CREATED
        )


class BasicCRUD(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user = request.user
        data = request.data

        if not check_password(data.get("old_password"), user.password):
            return Response(
                {"message": "old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = UpdateUserSerializer(instance=user, data=data, partial=True)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        return Response({"message": "User Updated"}, status=status.HTTP_200_OK)

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "user deleted successfully"})


class AdminPrev(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        users = CustomUser.objects.all()
        serializer = UserSerializer(users, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, user_id):
        data = request.data
        user = CustomUser.objects.get(id=user_id)
        serializer = AdminUpdateSerializer(instance=user, data=data)

        if not serializer.is_valid():
            return Response(
                {"message": "enter valid type"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer.save()
        return Response({"message": "user status updated"}, status=status.HTTP_200_OK)


class ForgotPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        user = CustomUser.objects.filter(email=email).first()

        if not user:
            return Response(
                f"User with Email {email} does not exist",
                status=status.HTTP_400_BAD_REQUEST,
            )
        token = SmtpMail.create_reset_token(self, user.email)
        SmtpMail.send_reset_email(self, email, token)

        return Response({"message": "email sent successfully", "token": token})


class ResetPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        token = data["token"]
        email = SmtpMail.verify_reset_token(self, token)

        if not email:
            return Response(
                {"message": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST
            )

        user = CustomUser.objects.get(email=email)
        if not user:
            return Response(
                f"User with Email {email} does not exist",
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        serializer = ResetRequestserializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(data["new_password"])
        user.save()
        return Response({"message": "password reset successfully"}, status=status.HTTP_200_OK)

