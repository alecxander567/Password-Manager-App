from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from vaults.models import Vault

from .models import Favorite
from .serializers import FavoriteSerializer


class FavoriteListView(generics.ListAPIView):
    serializer_class = FavoriteSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Favorite.objects.filter(user=self.request.user).select_related("vault")


class FavoriteToggleView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def _get_vault(self, request, vault_pk):
        return get_object_or_404(Vault, pk=vault_pk, owner=request.user)

    def post(self, request, vault_pk):
        vault = self._get_vault(request, vault_pk)
        favorite, created = Favorite.objects.get_or_create(
            user=request.user,
            vault=vault,
        )
        response_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(FavoriteSerializer(favorite).data, status=response_status)

    def delete(self, request, vault_pk):
        vault = self._get_vault(request, vault_pk)
        Favorite.objects.filter(user=request.user, vault=vault).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
