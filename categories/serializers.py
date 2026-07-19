from rest_framework import serializers

from .models import Category


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ["id", "name", "description", "user", "created_at", "updated_at"]
        read_only_fields = ["id", "user", "created_at", "updated_at"]


class SeedCategoriesSerializer(serializers.Serializer):
    created_count = serializers.IntegerField(read_only=True)
    skipped_count = serializers.IntegerField(read_only=True)