from rest_framework import serializers
from .models import Vault, Account


class VaultListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing vaults (no sensitive fields)."""
    class Meta:
        model = Vault
        fields = ["id", "name", "category", "biometric_enabled", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class VaultCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vault
        fields = ["id", "name", "category", "kdf_salt", "encrypted_vault_key", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]

    def create(self, validated_data):
        validated_data["owner"] = self.context["request"].user
        return super().create(validated_data)


class VaultDetailSerializer(serializers.ModelSerializer):
    """Returns salt + encrypted_vault_key for unlocking a vault."""
    class Meta:
        model = Vault
        fields = ["id", "name", "category", "kdf_salt", "encrypted_vault_key",
                  "biometric_enabled", "webauthn_credential_id",
                  "encrypted_vault_key_biometric", "created_at", "updated_at"]
        read_only_fields = fields


class AccountCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["id", "site_name", "encrypted_password", "iv_nonce", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]

    def create(self, validated_data):
        vault_id = self.context["view"].kwargs.get("vault_pk")
        validated_data["vault_id"] = vault_id
        return super().create(validated_data)


class AccountListSerializer(serializers.ModelSerializer):
    """Returns only account names (no encrypted data)."""
    class Meta:
        model = Account
        fields = ["id", "site_name", "created_at", "updated_at"]
        read_only_fields = fields


class AccountDetailSerializer(serializers.ModelSerializer):
    """Returns the full encrypted password blob for a single account."""
    class Meta:
        model = Account
        fields = ["id", "site_name", "encrypted_password", "iv_nonce", "created_at", "updated_at"]
        read_only_fields = fields