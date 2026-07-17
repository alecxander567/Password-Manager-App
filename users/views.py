from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    UserSerializer,
    ChangePasswordSerializer,
    UpdateUserSerializer,
)

User = get_user_model()


# ──────────────────────────────────────────────
#  Helper: generate JWT tokens for a user
# ──────────────────────────────────────────────
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


# ──────────────────────────────────────────────
#  Register
# ──────────────────────────────────────────────
class RegisterView(generics.CreateAPIView):
    """
    Create a new user account.
    Returns JWT tokens on success.
    """
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = serializer.save()
        except IntegrityError:
            return Response(
                {"error": "A user with that email or username already exists."},
                status=status.HTTP_409_CONFLICT,
            )
        except Exception as e:
            return Response(
                {"error": "An unexpected error occurred during registration."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data

        return Response(
            {
                "user": user_data,
                "access": tokens["access"],
                "refresh": tokens["refresh"],
            },
            status=status.HTTP_201_CREATED,
        )


# ──────────────────────────────────────────────
#  Login
# ──────────────────────────────────────────────
class LoginView(APIView):
    """
    Authenticate a user with email and password.
    Returns JWT tokens on success.
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data

        return Response(
            {
                "user": user_data,
                "access": tokens["access"],
                "refresh": tokens["refresh"],
            },
            status=status.HTTP_200_OK,
        )


# ──────────────────────────────────────────────
#  Logout (blacklist refresh token)
# ──────────────────────────────────────────────
class LogoutView(APIView):
    """
    Blacklist the provided refresh token.
    Requires authentication.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"error": "Invalid or expired refresh token."},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ──────────────────────────────────────────────
#  Get / Update current user profile
# ──────────────────────────────────────────────
class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Retrieve or update the authenticated user's profile.
    """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = UpdateUserSerializer(
            instance, data=request.data, partial=partial
        )
        serializer.is_valid(raise_exception=True)

        try:
            self.perform_update(serializer)
        except IntegrityError:
            return Response(
                {"error": "That username is already taken."},
                status=status.HTTP_409_CONFLICT,
            )
        except Exception as e:
            return Response(
                {"error": "An unexpected error occurred while updating your profile."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(UserSerializer(instance).data, status=status.HTTP_200_OK)


# ──────────────────────────────────────────────
#  Change password
# ──────────────────────────────────────────────
class ChangePasswordView(APIView):
    """
    Change the authenticated user's password.
    Requires old password verification.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        # Verify old password
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"old_password": "Old password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Set new password
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        # Keep the user logged in after password change
        update_session_auth_hash(request, user)

        # Issue new tokens
        tokens = get_tokens_for_user(user)

        return Response(
            {
                "detail": "Password changed successfully.",
                "access": tokens["access"],
                "refresh": tokens["refresh"],
            },
            status=status.HTTP_200_OK,
        )


# ──────────────────────────────────────────────
#  Delete account
# ──────────────────────────────────────────────
class DeleteAccountView(APIView):
    """
    Permanently delete the authenticated user's account.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def delete(self, request):
        user = request.user
        try:
            user.delete()
            return Response(
                {"detail": "Account deleted successfully."},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Exception as e:
            return Response(
                {"error": "An unexpected error occurred while deleting your account."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )