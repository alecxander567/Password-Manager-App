import json
import base64
import dataclasses
import hashlib
import hmac
import os
from django.conf import settings
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

from .models import Vault, Account
from .serializers import (
    VaultListSerializer,
    VaultCreateSerializer,
    VaultDetailSerializer,
    AccountCreateSerializer,
    AccountListSerializer,
    AccountDetailSerializer,
)

# -------------------------------------------------------------------
#  Vault Endpoints
# -------------------------------------------------------------------


class VaultListCreateView(generics.ListCreateAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get_serializer_class(self):
        if self.request.method == "POST":
            return VaultCreateSerializer
        return VaultListSerializer

    def get_queryset(self):
        return Vault.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class VaultDetailView(generics.RetrieveAPIView):
    serializer_class = VaultDetailSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Vault.objects.filter(owner=self.request.user)


class VaultUnlockView(APIView):
    """
    Verify the master password for a vault.
    User must be the vault owner (checked via JWT).
    """

    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, pk):
        vault = get_object_or_404(Vault, pk=pk, owner=request.user)
        master_password = request.data.get("master_password")

        if not master_password:
            return Response(
                {"error": "Master password is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.conf import settings
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        salt = base64.b64decode(vault.kdf_salt)
        iterations = 100000
        encrypted_vault_key = base64.b64decode(vault.encrypted_vault_key)
        nonce = encrypted_vault_key[:12]
        ciphertext_with_tag = encrypted_vault_key[12:]

        # Try the provided password first, then the user's email (for vaults created without custom password)
        passwords_to_try = [master_password, request.user.email]

        for pwd in passwords_to_try:
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=iterations,
                    backend=default_backend(),
                )
                derived_key = kdf.derive(pwd.encode("utf-8"))
                aesgcm = AESGCM(derived_key)
                decrypted_vault_key = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                request.session[f"unlocked_vault_key_{vault.id}"] = base64.b64encode(
                    decrypted_vault_key
                ).decode("utf-8")
                request.session.set_expiry(300)

                return Response(
                    {
                        "status": "success",
                        "message": "Vault unlocked successfully.",
                        "vault_id": vault.id,
                        "vault_name": vault.name,
                        "vault_key": base64.b64encode(decrypted_vault_key).decode(
                            "utf-8"
                        ),
                    },
                    status=status.HTTP_200_OK,
                )
            except Exception:
                continue

        return Response(
            {"error": "Invalid master password."},
            status=status.HTTP_400_BAD_REQUEST,
        )


# -------------------------------------------------------------------
#  Account Endpoints (nested under vaults)
# -------------------------------------------------------------------


class AccountListCreateView(generics.ListCreateAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get_serializer_class(self):
        if self.request.method == "POST":
            return AccountCreateSerializer
        return AccountListSerializer

    def get_queryset(self):
        vault = get_object_or_404(
            Vault, pk=self.kwargs["vault_pk"], owner=self.request.user
        )
        return Account.objects.filter(vault=vault)

    def perform_create(self, serializer):
        vault = get_object_or_404(
            Vault, pk=self.kwargs["vault_pk"], owner=self.request.user
        )
        serializer.save(vault=vault)


class AccountDetailView(generics.RetrieveAPIView):
    serializer_class = AccountDetailSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        vault = get_object_or_404(
            Vault, pk=self.kwargs["vault_pk"], owner=self.request.user
        )
        return Account.objects.filter(vault=vault)


class AccountUpdateView(generics.UpdateAPIView):
    serializer_class = AccountDetailSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        vault = get_object_or_404(
            Vault, pk=self.kwargs["vault_pk"], owner=self.request.user
        )
        return Account.objects.filter(vault=vault)

    def update(self, request, *args, **kwargs):
        # Check if WebAuthn authentication is required for this vault
        vault = get_object_or_404(Vault, pk=kwargs["vault_pk"], owner=request.user)

        # Check if WebAuthn authentication was recently completed
        webauthn_verified = request.session.get(
            f"webauthn_auth_verified_{vault.id}", False
        )
        if not webauthn_verified:
            return Response(
                {
                    "error": "WebAuthn authentication required.",
                    "message": "Please authenticate with biometrics before editing accounts.",
                    "vault_id": vault.id,
                    "requires_webauthn": True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # Clear the WebAuthn verification flag - must re-authenticate for next operation
        request.session.pop(f"webauthn_auth_verified_{vault.id}", None)

        return super().update(request, *args, **kwargs)


class AccountDeleteView(generics.DestroyAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        vault = get_object_or_404(
            Vault, pk=self.kwargs["vault_pk"], owner=self.request.user
        )
        return Account.objects.filter(vault=vault)

    def destroy(self, request, *args, **kwargs):
        # Check if WebAuthn authentication is required for this vault
        vault = get_object_or_404(Vault, pk=kwargs["vault_pk"], owner=request.user)

        # Check if WebAuthn authentication was recently completed
        webauthn_verified = request.session.get(
            f"webauthn_auth_verified_{vault.id}", False
        )
        if not webauthn_verified:
            return Response(
                {
                    "error": "WebAuthn authentication required.",
                    "message": "Please authenticate with biometrics before deleting accounts.",
                    "vault_id": vault.id,
                    "requires_webauthn": True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # Clear the WebAuthn verification flag - must re-authenticate for next operation
        request.session.pop(f"webauthn_auth_verified_{vault.id}", None)

        return super().destroy(request, *args, **kwargs)


# -------------------------------------------------------------------
#  WebAuthn Helpers
# -------------------------------------------------------------------


def _snake_to_camel(name):
    """Convert snake_case to camelCase."""
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def serialize_webauthn_options(obj):
    """Recursively serialize a dataclass with bytes/enums to a JSON-safe dict, with camelCase keys."""
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("utf-8")
    if isinstance(obj, dict):
        return {
            _snake_to_camel(k): serialize_webauthn_options(v) for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [serialize_webauthn_options(v) for v in obj]
    if dataclasses.is_dataclass(obj):
        return serialize_webauthn_options(dataclasses.asdict(obj))
    if hasattr(obj, "value"):
        return obj.value
    return obj


def _biometric_storage_key():
    return hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()


def _encrypt_biometric_vault_key(vault_key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    encrypted = AESGCM(_biometric_storage_key()).encrypt(nonce, vault_key, None)
    return "server:v1:" + base64.b64encode(nonce + encrypted).decode("utf-8")


def _decrypt_biometric_vault_key(value):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not value.startswith("server:v1:"):
        return value
    encrypted = base64.b64decode(value.removeprefix("server:v1:"))
    return base64.b64encode(
        AESGCM(_biometric_storage_key()).decrypt(encrypted[:12], encrypted[12:], None)
    ).decode("utf-8")


try:
    from webauthn import (
        generate_registration_options,
        verify_registration_response,
        generate_authentication_options,
        verify_authentication_response,
    )
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        AuthenticatorAttestationResponse,
        AuthenticatorAssertionResponse,
    )

    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False


# -------------------------------------------------------------------
#  WebAuthn Endpoints
# -------------------------------------------------------------------


class WebAuthnRegistrationOptionsView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, vault_pk):
        if not WEBAUTHN_AVAILABLE:
            return Response(
                {"error": "py_webauthn is not installed."},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        vault = get_object_or_404(Vault, pk=vault_pk, owner=request.user)
        user = request.user

        origin = request.META.get("HTTP_ORIGIN", "")
        if origin:
            from urllib.parse import urlparse

            parsed = urlparse(origin)
            rp_id = parsed.hostname or request.get_host().split(":")[0]
        else:
            rp_id = request.get_host().split(":")[0]

        rp_name = "Password Manager"

        user_id = f"user_{user.id}".encode("utf-8")
        user_name = user.email
        user_display_name = user.username or user.email

        try:
            options = generate_registration_options(
                rp_id=rp_id,
                rp_name=rp_name,
                user_name=user_name,
                user_id=user_id,
                user_display_name=user_display_name,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.PREFERRED,
                ),
            )

            challenge = options.challenge
            if isinstance(challenge, bytes):
                challenge = challenge.hex()
            request.session[f"webauthn_reg_challenge_{vault_pk}"] = challenge

            options_dict = serialize_webauthn_options(options)
            options_dict.pop("hints", None)
            return Response(options_dict, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to generate registration options: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class WebAuthnRegistrationVerifyView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, vault_pk):
        if not WEBAUTHN_AVAILABLE:
            return Response(
                {"error": "py_webauthn is not installed."},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        vault = get_object_or_404(Vault, pk=vault_pk, owner=request.user)

        challenge_hex = request.session.pop(f"webauthn_reg_challenge_{vault_pk}", None)
        if not challenge_hex:
            return Response(
                {"error": "No registration challenge found. Start registration first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            challenge = bytes.fromhex(challenge_hex)
            cd = request.data

            origin_header = request.META.get("HTTP_ORIGIN", "")
            if origin_header:
                from urllib.parse import urlparse

                parsed_origin = urlparse(origin_header)
                rp_id = parsed_origin.hostname or request.get_host().split(":")[0]
                origin = origin_header
            else:
                rp_id = request.get_host().split(":")[0]
                origin = (
                    f"https://{rp_id}"
                    if "localhost" not in rp_id
                    else f"http://{rp_id}"
                )

            verification = verify_registration_response(
                credential={
                    "id": cd["id"],
                    "rawId": cd.get("rawId", cd["id"]),
                    "response": {
                        "clientDataJSON": cd["response"]["clientDataJSON"],
                        "attestationObject": cd["response"]["attestationObject"],
                    },
                    "type": "public-key",
                },
                expected_challenge=challenge,
                expected_rp_id=rp_id,
                expected_origin=origin,
            )

            vault.webauthn_credential_id = verification.credential_id.hex()
            vault.webauthn_credential_public_key = base64.b64encode(
                verification.credential_public_key
            ).decode("utf-8")
            vault.biometric_enabled = True

            encrypted_vault_key_biometric = request.data.get(
                "encrypted_vault_key_biometric"
            )
            if encrypted_vault_key_biometric:
                vault.encrypted_vault_key_biometric = encrypted_vault_key_biometric
            else:
                master_password = request.data.get("master_password")
                if master_password:
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    salt = base64.b64decode(vault.kdf_salt)
                    encrypted_vault_key = base64.b64decode(vault.encrypted_vault_key)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend(),
                    )
                    derived_key = kdf.derive(master_password.encode("utf-8"))
                    vault_key = AESGCM(derived_key).decrypt(
                        encrypted_vault_key[:12], encrypted_vault_key[12:], None
                    )
                else:
                    unlocked_vault_key = request.session.get(
                        f"unlocked_vault_key_{vault.id}"
                    )
                    if not unlocked_vault_key:
                        return Response(
                            {
                                "error": "Unlock the vault with the master password before registering biometrics."
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                    vault_key = base64.b64decode(unlocked_vault_key)

                vault.encrypted_vault_key_biometric = _encrypt_biometric_vault_key(
                    vault_key
                )

            vault.save()

            return Response(
                {"status": "success", "credential_id": vault.webauthn_credential_id},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": f"Registration verification failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class WebAuthnAuthenticationOptionsView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, vault_pk):
        if not WEBAUTHN_AVAILABLE:
            return Response(
                {"error": "py_webauthn is not installed."},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        vault = get_object_or_404(Vault, pk=vault_pk, owner=request.user)

        if not vault.webauthn_credential_id:
            return Response(
                {"error": "No WebAuthn credential registered for this vault."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        origin = request.META.get("HTTP_ORIGIN", "")
        if origin:
            from urllib.parse import urlparse

            parsed = urlparse(origin)
            rp_id = parsed.hostname or request.get_host().split(":")[0]
        else:
            rp_id = request.get_host().split(":")[0]

        try:
            options = generate_authentication_options(
                rp_id=rp_id,
                user_verification=UserVerificationRequirement.PREFERRED,
            )

            challenge = options.challenge
            if isinstance(challenge, bytes):
                challenge = challenge.hex()
            request.session[f"webauthn_auth_challenge_{vault_pk}"] = challenge

            options_dict = serialize_webauthn_options(options)
            return Response(options_dict, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to generate authentication options: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class WebAuthnAuthenticationVerifyView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, vault_pk):
        if not WEBAUTHN_AVAILABLE:
            return Response(
                {"error": "py_webauthn is not installed."},
                status=status.HTTP_501_NOT_IMPLEMENTED,
            )

        vault = get_object_or_404(Vault, pk=vault_pk, owner=request.user)

        if not vault.webauthn_credential_id:
            return Response(
                {"error": "No WebAuthn credential registered for this vault."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        challenge_hex = request.session.pop(f"webauthn_auth_challenge_{vault_pk}", None)
        if not challenge_hex:
            return Response(
                {
                    "error": "No authentication challenge found. Start authentication first."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            challenge = bytes.fromhex(challenge_hex)
            cd = request.data

            origin_header = request.META.get("HTTP_ORIGIN", "")
            if origin_header:
                from urllib.parse import urlparse

                parsed_origin = urlparse(origin_header)
                rp_id = parsed_origin.hostname or request.get_host().split(":")[0]
                origin = origin_header
            else:
                rp_id = request.get_host().split(":")[0]
                origin = (
                    f"https://{rp_id}"
                    if "localhost" not in rp_id
                    else f"http://{rp_id}"
                )

            credential_public_key = (
                base64.b64decode(vault.webauthn_credential_public_key)
                if vault.webauthn_credential_public_key
                else b""
            )

            verification = verify_authentication_response(
                credential={
                    "id": cd["id"],
                    "rawId": cd.get("rawId", cd["id"]),
                    "response": {
                        "clientDataJSON": cd["response"]["clientDataJSON"],
                        "authenticatorData": cd["response"]["authenticatorData"],
                        "signature": cd["response"]["signature"],
                    },
                    "type": "public-key",
                },
                expected_challenge=challenge,
                expected_rp_id=rp_id,
                expected_origin=origin,
                credential_public_key=credential_public_key,
                credential_current_sign_count=0,
            )

            # Mark this vault as WebAuthn verified for sensitive operations
            request.session[f"webauthn_auth_verified_{vault_pk}"] = True
            request.session.set_expiry(300)

            # Return the vault key for biometric unlock
            if not vault.encrypted_vault_key_biometric:
                return Response(
                    {
                        "status": "success",
                        "verified": True,
                        "vault_key": None,
                        "message": "No biometric vault key found. Please register biometrics first.",
                    },
                    status=status.HTTP_200_OK,
                )

            return Response(
                {
                    "status": "success",
                    "verified": True,
                    "vault_key": _decrypt_biometric_vault_key(
                        vault.encrypted_vault_key_biometric
                    ),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": f"Authentication verification failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
