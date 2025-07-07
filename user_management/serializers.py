from rest_framework import serializers

import re

from user_management.models import CustomUser


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


def validate_password(value):
    if len(value) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long")

    if not re.search(r"[A-Z]", value):
        raise serializers.ValidationError(
            "Password must contain at least one upper case letter"
        )
    if not re.search(r"[a-z]", value):
        raise serializers.ValidationError(
            "Password must contain at least one lower case letter"
        )
    if not re.search(r"\d", value):
        raise serializers.ValidationError("Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*()/+\-?"{}<>,.]', value):
        raise serializers.ValidationError(
            "Password must contain at least one special character"
        )

    return value


class SignupSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ["username", "email", "first_name", "last_name", "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_password(self, value):
        return validate_password(value)

    def create(self, validated_data):
        user = CustomUser(
            username=validated_data["username"],
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
        )
        user.set_password(validated_data["password"])
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        exclude = ["password"]


class UpdateUserSerializer(serializers.Serializer):

    class Meta:
        model = CustomUser
        fields = ["first_name", "last_name", "old_password", "new_password"]

    def validate_password(self, value):
        return validate_password(value)

    def update(self, instance, validated_data):  # instance is user object
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        password = validated_data.get("new_password")
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class AdminUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ["is_active"]

    def update(self, instance, validated_data):
        instance.is_active = validated_data.get("is_active", instance.is_active)
        instance.save()
        return instance


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetRequestserializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError("Password does not match")

        validate_password(data["new_password"])
        return data
