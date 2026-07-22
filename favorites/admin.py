from django.contrib import admin

from .models import Favorite


@admin.register(Favorite)
class FavoriteAdmin(admin.ModelAdmin):
    list_display = ("user", "vault", "created_at")
    list_filter = ("created_at",)
    search_fields = ("user__email", "vault__name")
