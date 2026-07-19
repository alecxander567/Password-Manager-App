from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Category
from .serializers import CategorySerializer, SeedCategoriesSerializer

DEFAULT_CATEGORIES = [
    {"name": "Social", "description": "Social media accounts (Facebook, Twitter, Instagram, etc.)"},
    {"name": "Email", "description": "Email accounts (Gmail, Outlook, Yahoo, etc.)"},
    {"name": "Work", "description": "Work-related accounts and credentials"},
    {"name": "Finance", "description": "Banking, credit cards, and financial services"},
    {"name": "Shopping", "description": "Online shopping accounts (Amazon, eBay, etc.)"},
    {"name": "Entertainment", "description": "Streaming services, gaming, and entertainment platforms"},
    {"name": "Education", "description": "E-learning platforms and educational resources"},
    {"name": "Health", "description": "Health and fitness accounts"},
    {"name": "Travel", "description": "Travel booking and accommodation accounts"},
    {"name": "Other", "description": "Miscellaneous accounts not covered by other categories"},
]


class CategoryListCreateView(generics.ListCreateAPIView):
    """
    List all categories for the authenticated user, or create a new category.
    """
    serializer_class = CategorySerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Category.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CategoryDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a category instance.
    """
    serializer_class = CategorySerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Category.objects.filter(user=self.request.user)


class SeedCategoriesView(APIView):
    """
    POST endpoint to seed default categories for the authenticated user.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        user = request.user
        created_count = 0
        skipped_count = 0

        for cat_data in DEFAULT_CATEGORIES:
            category, created = Category.objects.get_or_create(
                name=cat_data["name"],
                user=user,
                defaults={"description": cat_data["description"]},
            )
            if created:
                created_count += 1
            else:
                skipped_count += 1

        serializer = SeedCategoriesSerializer(data={
            "created_count": created_count,
            "skipped_count": skipped_count,
        })
        serializer.is_valid()

        return Response(serializer.data, status=status.HTTP_201_CREATED)
