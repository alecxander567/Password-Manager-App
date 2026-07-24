from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions as django_exceptions
from django.core.validators import validate_email

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
    )

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "password2", "bio")

    def validate(self, attrs):
        if attrs["password"] != attrs.pop("password2"):
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
        write_only=True,
    )

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            user = authenticate(
                request=self.context.get("request"),
                email=email,
                password=password,
            )
            if not user:
                msg = "Unable to log in with provided credentials."
                raise serializers.ValidationError(msg, code="authorization")
        else:
            msg = 'Must include "email" and "password".'
            raise serializers.ValidationError(msg, code="authorization")

        attrs["user"] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "bio", "created_at", "updated_at")
        read_only_fields = ("id", "created_at", "updated_at")


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={"input_type": "password"},
    )
    new_password2 = serializers.CharField(
        required=True,
        style={"input_type": "password"},
    )

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError(
                {"new_password": "New passwords do not match."}
            )
        return attrs


class UpdateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False, validators=[validate_email])

    class Meta:
        model = User
        fields = ("username", "email", "bio")
        extra_kwargs = {
            "username": {"required": False},
            "email": {"required": False},
            "bio": {"required": False},
        }

    def validate_username(self, value):
        """Validate that the username is unique and follows the correct format."""
        if value:
            # Trim whitespace
            value = value.strip()

            # Check if username is taken
            user_id = self.instance.id if self.instance else None
            if User.objects.filter(username=value).exclude(id=user_id).exists():
                raise serializers.ValidationError(
                    "A user with this username already exists."
                )

            # Validate username length
            if len(value) < 3:
                raise serializers.ValidationError(
                    "Username must be at least 3 characters long."
                )
            if len(value) > 150:
                raise serializers.ValidationError(
                    "Username must be at most 150 characters long."
                )

            # Django's User model automatically validates the username format
            # Valid characters: letters, numbers, and @/./+/-/_

        return value

    def validate_email(self, value):
        """Validate that the email is unique."""
        if value:
            # Trim whitespace
            value = value.strip()

            # Check if email is taken
            user_id = self.instance.id if self.instance else None
            if User.objects.filter(email=value).exclude(id=user_id).exists():
                raise serializers.ValidationError(
                    "A user with this email already exists."
                )

        return value

    def validate_bio(self, value):
        """Validate bio length."""
        if value:
            value = value.strip()
            if len(value) > 500:
                raise serializers.ValidationError(
                    "Bio must be at most 500 characters long."
                )
        return value

    def validate(self, attrs):
        """Validate that at least one field is being updated."""
        if not attrs:
            raise serializers.ValidationError("No fields to update.")
        return attrs
