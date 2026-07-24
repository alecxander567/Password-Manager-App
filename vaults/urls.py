from django.urls import path
from . import views

urlpatterns = [
    # IMPORTANT: Dashboard stats MUST come BEFORE the main vault pattern
    path(
        "dashboard/stats/",
        views.DashboardStatsView.as_view(),
        name="dashboard-stats",
    ),
    # Password endpoints
    path(
        "password-generate/",
        views.PasswordGenerateView.as_view(),
        name="password-generate",
    ),
    path(
        "password-strength/",
        views.PasswordStrengthCheckView.as_view(),
        name="password-strength-check",
    ),
    # Vault endpoints
    path("", views.VaultListCreateView.as_view(), name="vault-list-create"),
    path("<int:pk>/", views.VaultDetailView.as_view(), name="vault-detail"),
    path("<int:pk>/unlock/", views.VaultUnlockView.as_view(), name="vault-unlock"),
    # Account endpoints (nested under vaults)
    path(
        "<int:vault_pk>/accounts/",
        views.AccountListCreateView.as_view(),
        name="account-list-create",
    ),
    path(
        "<int:vault_pk>/accounts/<int:pk>/",
        views.AccountDetailView.as_view(),
        name="account-detail",
    ),
    path(
        "<int:vault_pk>/accounts/<int:pk>/update/",
        views.AccountUpdateView.as_view(),
        name="account-update",
    ),
    path(
        "<int:vault_pk>/accounts/<int:pk>/delete/",
        views.AccountDeleteView.as_view(),
        name="account-delete",
    ),
    # WebAuthn endpoints
    path(
        "<int:vault_pk>/webauthn/register/options/",
        views.WebAuthnRegistrationOptionsView.as_view(),
        name="webauthn-register-options",
    ),
    path(
        "<int:vault_pk>/webauthn/register/verify/",
        views.WebAuthnRegistrationVerifyView.as_view(),
        name="webauthn-register-verify",
    ),
    path(
        "<int:vault_pk>/webauthn/authenticate/options/",
        views.WebAuthnAuthenticationOptionsView.as_view(),
        name="webauthn-auth-options",
    ),
    path(
        "<int:vault_pk>/webauthn/authenticate/verify/",
        views.WebAuthnAuthenticationVerifyView.as_view(),
        name="webauthn-auth-verify",
    ),
]
