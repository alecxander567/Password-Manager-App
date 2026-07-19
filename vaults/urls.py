from django.urls import path
from . import views

urlpatterns = [
    # Vault endpoints
    path("", views.VaultListCreateView.as_view(), name="vault-list-create"),
    path("<int:pk>/", views.VaultDetailView.as_view(), name="vault-detail"),
    # Account endpoints (nested under vaults)
    path("<int:vault_pk>/accounts/", views.AccountListCreateView.as_view(), name="account-list-create"),
    path("<int:vault_pk>/accounts/<int:pk>/", views.AccountDetailView.as_view(), name="account-detail"),
    # WebAuthn endpoints
    path("<int:vault_pk>/webauthn/register/options/", views.WebAuthnRegistrationOptionsView.as_view(), name="webauthn-register-options"),
    path("<int:vault_pk>/webauthn/register/verify/", views.WebAuthnRegistrationVerifyView.as_view(), name="webauthn-register-verify"),
    path("<int:vault_pk>/webauthn/authenticate/options/", views.WebAuthnAuthenticationOptionsView.as_view(), name="webauthn-auth-options"),
    path("<int:vault_pk>/webauthn/authenticate/verify/", views.WebAuthnAuthenticationVerifyView.as_view(), name="webauthn-auth-verify"),
]