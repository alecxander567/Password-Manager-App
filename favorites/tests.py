from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from vaults.models import Vault

from .models import Favorite


class FavoriteAPITests(APITestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="owner@example.com",
            username="owner",
            password="strong-password",
        )
        self.other_user = get_user_model().objects.create_user(
            email="other@example.com",
            username="other",
            password="strong-password",
        )
        self.vault = Vault.objects.create(
            name="Personal",
            category="private",
            owner=self.user,
            kdf_salt="salt",
            encrypted_vault_key="encrypted-key",
        )
        self.client.force_authenticate(self.user)

    def test_user_can_list_mark_and_unmark_a_vault(self):
        list_url = reverse("favorite-list")
        toggle_url = reverse("favorite-toggle", kwargs={"vault_pk": self.vault.pk})

        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

        response = self.client.post(toggle_url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["vault"]["id"], self.vault.pk)
        self.assertTrue(
            Favorite.objects.filter(user=self.user, vault=self.vault).exists()
        )

        response = self.client.post(toggle_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            Favorite.objects.filter(user=self.user, vault=self.vault).count(), 1
        )

        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

        response = self.client.delete(toggle_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            Favorite.objects.filter(user=self.user, vault=self.vault).exists()
        )

    def test_user_cannot_favorite_another_users_vault(self):
        other_vault = Vault.objects.create(
            name="Other",
            category="private",
            owner=self.other_user,
            kdf_salt="salt",
            encrypted_vault_key="encrypted-key",
        )
        toggle_url = reverse("favorite-toggle", kwargs={"vault_pk": other_vault.pk})

        response = self.client.post(toggle_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(
            Favorite.objects.filter(user=self.user, vault=other_vault).exists()
        )
