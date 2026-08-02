from rest_framework import serializers
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import Vault, Account


class VaultListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing vaults (no sensitive fields)."""

    class Meta:
        model = Vault
        fields = [
            "id",
            "name",
            "category",
            "biometric_enabled",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class VaultCreateSerializer(serializers.ModelSerializer):
    master_password = serializers.CharField(
        write_only=True, required=False, allow_blank=True
    )

    class Meta:
        model = Vault
        fields = [
            "id",
            "name",
            "category",
            "master_password",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def create(self, validated_data):
        master_password = validated_data.pop("master_password", None)

        if not master_password or not master_password.strip():
            master_password = self.context["request"].user.email

        salt = os.urandom(16)
        kdf_salt = base64.b64encode(salt).decode("utf-8")
        iterations = 100000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        derived_key = kdf.derive(master_password.encode("utf-8"))
        vault_key = os.urandom(32)
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        encrypted_vault_key_bytes = aesgcm.encrypt(nonce, vault_key, None)
        validated_data["kdf_salt"] = kdf_salt
        validated_data["encrypted_vault_key"] = base64.b64encode(
            nonce + encrypted_vault_key_bytes
        ).decode("utf-8")

        validated_data["owner"] = self.context["request"].user
        return Vault.objects.create(**validated_data)


class VaultDetailSerializer(serializers.ModelSerializer):
    """Returns salt + encrypted_vault_key for unlocking a vault."""

    class Meta:
        model = Vault
        fields = [
            "id",
            "name",
            "category",
            "kdf_salt",
            "encrypted_vault_key",
            "biometric_enabled",
            "webauthn_credential_id",
            "encrypted_vault_key_biometric",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AccountCreateSerializer(serializers.ModelSerializer):
    password_strength_score = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True,
        help_text="Password strength score (0-100) evaluated client-side.",
    )

    class Meta:
        model = Account
        fields = [
            "id",
            "site_name",
            "encrypted_password",
            "iv_nonce",
            "password_strength_score",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def create(self, validated_data):
        password_strength_score = validated_data.pop("password_strength_score", None)
        if password_strength_score is not None:
            validated_data["password_strength"] = password_strength_score
        vault_id = self.context["view"].kwargs.get("vault_pk")
        validated_data["vault_id"] = vault_id
        return super().create(validated_data)


class AccountListSerializer(serializers.ModelSerializer):
    """Returns only account names (no encrypted data)."""

    password_strength_label = serializers.SerializerMethodField()

    class Meta:
        model = Account
        fields = [
            "id",
            "site_name",
            "password_strength",
            "password_strength_label",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "password_strength",
            "password_strength_label",
            "created_at",
            "updated_at",
        ]

    def get_password_strength_label(self, obj):
        if obj.password_strength is not None:
            from vaults.utils import get_strength_label

            return get_strength_label(obj.password_strength)
        return None


class AccountUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating an account (site_name and encrypted data)."""

    password_strength_score = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True,
        help_text="Password strength score (0-100) evaluated client-side.",
    )

    class Meta:
        model = Account
        fields = [
            "id",
            "site_name",
            "encrypted_password",
            "iv_nonce",
            "password_strength_score",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def update(self, instance, validated_data):
        password_strength_score = validated_data.pop("password_strength_score", None)
        if password_strength_score is not None:
            validated_data["password_strength"] = password_strength_score
        return super().update(instance, validated_data)


class AccountDetailSerializer(serializers.ModelSerializer):
    """Returns the full encrypted password blob for a single account."""

    password_strength_label = serializers.SerializerMethodField()

    class Meta:
        model = Account
        fields = [
            "id",
            "site_name",
            "encrypted_password",
            "iv_nonce",
            "password_strength",
            "password_strength_label",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_password_strength_label(self, obj):
        if obj.password_strength is not None:
            from vaults.utils import get_strength_label

            return get_strength_label(obj.password_strength)
        return None
