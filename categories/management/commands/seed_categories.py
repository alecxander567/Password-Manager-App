from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

from categories.models import Category

User = get_user_model()

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


class Command(BaseCommand):
    help = "Seed default categories for all existing users"

    def handle(self, *args, **options):
        users = User.objects.all()

        if not users.exists():
            self.stdout.write(
                self.style.WARNING("No users found. Create a user first then run this command again.")
            )
            return

        created_count = 0
        skipped_count = 0

        for user in users:
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

        self.stdout.write(
            self.style.SUCCESS(
                f"Done! Created {created_count} categories, skipped {skipped_count} existing."
            )
        )