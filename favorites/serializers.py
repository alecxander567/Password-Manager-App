from rest_framework import serializers

from vaults.serializers import VaultListSerializer

from .models import Favorite


class FavoriteSerializer(serializers.ModelSerializer):
    vault = VaultListSerializer(read_only=True)

    class Meta:
        model = Favorite
        fields = ["id", "vault", "created_at"]
        read_only_fields = fields
