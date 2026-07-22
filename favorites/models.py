from django.conf import settings
from django.db import models

from vaults.models import Vault


class Favorite(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="favorite_vaults",
    )
    vault = models.ForeignKey(
        Vault,
        on_delete=models.CASCADE,
        related_name="favorited_by",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "favorites"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "vault"],
                name="unique_favorite_per_user_vault",
            ),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.vault.name}"
