from django.urls import path
from . import views

urlpatterns = [
    path("", views.CategoryListCreateView.as_view(), name="category-list-create"),
    path("seed/", views.SeedCategoriesView.as_view(), name="category-seed"),
    path("<int:pk>/", views.CategoryDetailView.as_view(), name="category-detail"),
]
