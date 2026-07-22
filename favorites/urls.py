from django.urls import path

from . import views

urlpatterns = [
    path("", views.FavoriteListView.as_view(), name="favorite-list"),
    path("<int:vault_pk>/", views.FavoriteToggleView.as_view(), name="favorite-toggle"),
]
