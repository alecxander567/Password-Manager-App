from django.db import models
from django.conf import settings


class Vault(models.Model):
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=100)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vaults",
    )
    kdf_salt = models.TextField()
    encrypted_vault_key = models.TextField()
    biometric_enabled = models.BooleanField(default=False)
    webauthn_credential_id = models.TextField(null=True, blank=True)
    webauthn_credential_public_key = models.TextField(null=True, blank=True)
    encrypted_vault_key_biometric = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "vaults"
        verbose_name = "Vault"
        verbose_name_plural = "Vaults"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.owner.email})"


class Account(models.Model):
    vault = models.ForeignKey(
        Vault,
        on_delete=models.CASCADE,
        related_name="accounts",
    )
    site_name = models.CharField(max_length=255)
    encrypted_password = models.TextField()
    iv_nonce = models.TextField()
    password_strength = models.IntegerField(
        null=True,
        blank=True,
        help_text="Password strength score (0-100). Null if not evaluated.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "accounts"
        verbose_name = "Account"
        verbose_name_plural = "Accounts"
        ordering = ["site_name"]

    def __str__(self):
        return f"{self.site_name} (in {self.vault.name})"