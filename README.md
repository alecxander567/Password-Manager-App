# 🔐 Password Manager API

A secure, production-ready Django REST Framework backend for a password management application with end-to-end encryption, biometric authentication, and advanced security features.

## 📋 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Deployment](#deployment)
- [Development](#development)

---

## ✨ Features

### 🔑 User Authentication & Management
- **JWT-based Authentication** - Secure token-based auth with access/refresh tokens
- **Email-based Login** - Users sign in with email instead of username
- **User Profiles** - Manage username, email, and bio
- **Password Management** - Change password with old password verification
- **Account Deletion** - Permanently delete user accounts with token cleanup

### 🏦 Vault Management
- **Multiple Vaults** - Create and manage multiple password vaults
- **Master Password Protection** - Each vault secured with a master password
- **Vault Categories** - Organize vaults with custom categories
- **Favorites System** - Mark frequently used vaults as favorites
- **Dashboard Statistics** - View security metrics across all vaults

### 🔒 Advanced Security
- **End-to-End Encryption** - AES-GCM encryption for vault keys and passwords
- **PBKDF2 Key Derivation** - 100,000 iterations for master password hashing
- **WebAuthn/Biometric Auth** - Support for fingerprint, Face ID, and hardware keys
- **Session-based Vault Unlocking** - Temporary vault access with 5-minute expiry
- **Password Strength Analysis** - Real-time strength scoring (0-100)

### 🎲 Password Generation
- **Cryptographically Secure** - Uses Python's `secrets` module (CSPRNG)
- **Multiple Generation Modes**:
  - **Password Mode** - Customizable length (8-128 chars)
  - **PIN Mode** - Numeric PIN codes (4-32 digits)
  - **Passphrase Mode** - Memorable word-based passwords
- **Customizable Options**:
  - Include/exclude uppercase, lowercase, digits, special characters
  - Exclude confusing characters (Il1O0)
  - Set minimum character type requirements
  - Custom character exclusions
- **Entropy-based Generation** - Generate passwords meeting minimum entropy thresholds

### 📊 Password Strength Evaluation
- **Real-time Scoring** - 0-100 strength score
- **Strength Categories**:
  - Strong (70-100)
  - Medium (50-69)
  - Weak (0-49)
- **Detailed Feedback** - Actionable suggestions for improvement

### 🗂️ Account Management
- **Secure Account Storage** - Encrypted passwords with IV nonces
- **Site Name Tracking** - Organize accounts by website/service
- **Password Strength Tracking** - Automatic strength evaluation on save
- **CRUD Operations** - Full create, read, update, delete functionality

### ⭐ Favorites System
- **Quick Access** - Mark vaults as favorites for fast retrieval
- **Unique Constraints** - One favorite per user-vault combination
- **Easy Toggle** - Add/remove favorites with single API call

---

## 🛠️ Tech Stack

### Backend
- **Django 6.0.7** - Web framework
- **Django REST Framework 3.17.1** - REST API toolkit
- **SimpleJWT 5.5.1** - JWT authentication
- **PostgreSQL** - Primary database (via psycopg2-binary)
- **Cryptography 49.0.0** - Encryption/decryption operations
- **WebAuthn 3.0.0** - Biometric authentication support

### Security & Deployment
- **WhiteNoise 6.12.0** - Static file serving
- **Django CORS Headers** - Cross-origin resource sharing
- **python-dotenv** - Environment variable management
- **dj-database-url** - Database URL configuration
- **Gunicorn 21.2.0** - WSGI HTTP server

---

## 🏗️ Architecture

### Project Structure
```
password-manager/
├── password_manager/          # Project configuration
│   ├── settings.py            # Django settings
│   ├── urls.py                # Root URL configuration
│   └── wsgi.py                # WSGI application
├── users/                     # User authentication app
│   ├── models.py              # Custom User model
│   ├── views.py               # Auth endpoints
│   ├── serializers.py         # User serializers
│   └── urls.py                # User API routes
├── vaults/                    # Vault management app
│   ├── models.py              # Vault & Account models
│   ├── views.py               # Vault operations & WebAuthn
│   ├── serializers.py         # Vault serializers
│   ├── utils/                 # Utility functions
│   │   ├── password_generator.py  # Secure password generation
│   │   └── password_strength.py   # Strength evaluation
│   └── urls.py                # Vault API routes
├── categories/                # Category management app
│   ├── models.py              # Category model
│   ├── views.py               # Category endpoints
│   └── urls.py                # Category API routes
├── favorites/                 # Favorites system app
│   ├── models.py              # Favorite model
│   ├── views.py               # Favorite endpoints
│   └── urls.py                # Favorite API routes
├── api/                       # API root view
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variables template
└── manage.py                  # Django management script
```

### App Responsibilities

#### **users** - Authentication & User Management
- User registration with email verification
- JWT token-based login/logout
- Profile management
- Password change functionality
- Account deletion

#### **vaults** - Core Password Management
- Vault creation with master password encryption
- Account CRUD operations within vaults
- Password generation (password, PIN, passphrase)
- Password strength evaluation
- WebAuthn biometric registration & authentication
- Dashboard statistics

#### **categories** - Organization
- User-specific categories
- Organize vaults by type (Personal, Work, Finance, etc.)

#### **favorites** - Quick Access
- Mark/unmark vaults as favorites
- Retrieve favorite vaults list

---

## 🔒 Security Features

### Encryption Strategy
1. **Vault Key Encryption**
   - Master password → PBKDF2 (100k iterations) → AES-256-GCM key
   - Vault key encrypted with derived key
   - Salt stored in database for key derivation

2. **Password Storage**
   - Each account password encrypted with unique IV (12 bytes)
   - AES-256-GCM authenticated encryption
   - IV nonce stored alongside ciphertext

3. **Biometric Vault Key**
   - Vault key encrypted with server-side key (SHA-256 of SECRET_KEY)
   - Stored only after WebAuthn registration
   - Decrypted after successful biometric authentication

### Authentication Flow
```
1. User Login
   ↓
2. JWT Tokens Issued (Access: 30min, Refresh: 7 days)
   ↓
3. Vault Unlock Request (master password)
   ↓
4. PBKDF2 derives key from master password
   ↓
5. AES-GCM decrypts vault key
   ↓
6. Vault key stored in session (5-min expiry)
   ↓
7. Account operations use vault key for encryption/decryption
```

### WebAuthn Biometric Flow
```
1. User enables biometrics on vault
   ↓
2. Server generates WebAuthn registration options
   ↓
3. Client creates credential (fingerprint/Face ID)
   ↓
4. Server verifies registration response
   ↓
5. Vault key encrypted with server key and stored
   ↓
6. Future vault unlock: biometric auth → retrieve encrypted vault key → decrypt
```

### Security Best Practices
- ✅ No plaintext passwords stored anywhere
- ✅ Master password never transmitted after initial vault creation
- ✅ Session-based vault key storage (auto-expiry)
- ✅ WebAuthn required for sensitive operations (edit/delete)
- ✅ JWT token rotation on password change
- ✅ Refresh token blacklisting on logout
- ✅ CORS configured for specific origins only
- ✅ CSRF protection enabled
- ✅ Secure cookie settings (HttpOnly, SameSite, Secure)
- ✅ HSTS enabled in production
- ✅ SSL redirect enforced in production

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- PostgreSQL 12+
- pip/virtualenv

### Setup Steps

1. **Clone the repository**
```bash
git clone https://github.com/alecxander567/Password-Manager-App.git
cd Password-Manager-App
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your database credentials and secret key
```

5. **Run migrations**
```bash
python manage.py migrate
```

6. **Create superuser (optional)**
```bash
python manage.py createsuperuser
```

7. **Seed categories (optional)**
```bash
python manage.py seed_categories
```

8. **Start development server**
```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/api/`

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True

# Database (PostgreSQL)
DB_NAME=password_manager
DB_USER=postgres
DB_PASSWORD=your-password
DB_HOST=localhost
DB_PORT=5432

# Alternative: Use DATABASE_URL for Render
# DATABASE_URL=postgres://user:pass@host:5432/dbname

# CORS Settings (add your frontend URL)
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

### Production Settings

For production deployment (e.g., Render):

1. Set `DEBUG=False`
2. Configure `ALLOWED_HOSTS` with your domain
3. Set `DATABASE_URL` environment variable
4. Ensure `SECRET_KEY` is strong and unique
5. Enable SSL redirect (automatic with `not DEBUG`)

---

## 📡 API Endpoints

### Base URL
```
http://localhost:8000/api/
```

### Authentication Endpoints (`/api/users/`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/users/register/` | Register new user | No |
| POST | `/api/users/login/` | Login with email/password | No |
| POST | `/api/users/logout/` | Logout (blacklist refresh token) | Yes |
| GET | `/api/users/profile/` | Get current user profile | Yes |
| PUT/PATCH | `/api/users/profile/` | Update user profile | Yes |
| POST | `/api/users/change-password/` | Change password | Yes |
| DELETE | `/api/users/delete-account/` | Delete account | Yes |

### Vault Endpoints (`/api/vaults/`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/vaults/` | List user's vaults | Yes |
| POST | `/api/vaults/` | Create new vault | Yes |
| GET | `/api/vaults/{id}/` | Get vault details | Yes |
| POST | `/api/vaults/{id}/unlock/` | Unlock vault with master password | Yes |
| POST | `/api/vaults/{id}/webauthn/registration/options/` | Get WebAuthn registration options | Yes |
| POST | `/api/vaults/{id}/webauthn/registration/verify/` | Verify WebAuthn registration | Yes |
| POST | `/api/vaults/{id}/webauthn/authentication/options/` | Get WebAuthn auth options | Yes |
| POST | `/api/vaults/{id}/webauthn/authentication/verify/` | Verify WebAuthn authentication | Yes |

### Account Endpoints (`/api/vaults/{vault_pk}/accounts/`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/vaults/{vault_pk}/accounts/` | List accounts in vault | Yes |
| POST | `/api/vaults/{vault_pk}/accounts/` | Create new account | Yes |
| GET | `/api/vaults/{vault_pk}/accounts/{id}/` | Get account details | Yes |
| PUT/PATCH | `/api/vaults/{vault_pk}/accounts/{id}/` | Update account | Yes* |
| DELETE | `/api/vaults/{vault_pk}/accounts/{id}/` | Delete account | Yes* |

*Requires WebAuthn authentication if vault has biometrics enabled

### Password Tools (`/api/vaults/`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/vaults/generate-password/` | Generate secure password | Yes |
| POST | `/api/vaults/check-password-strength/` | Evaluate password strength | Yes |
| GET | `/api/vaults/dashboard-stats/` | Get dashboard statistics | Yes |

### Category Endpoints (`/api/categories/`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/categories/` | List user's categories | Yes |
| POST | `/api/categories/` | Create new category | Yes |
| GET | `/api/categories/{id}/` | Get category details | Yes |
| PUT/PATCH | `/api/categories/{id}/` | Update category | Yes |
| DELETE | `/api/categories/{id}/` | Delete category | Yes |

### Favorite Endpoints (`/api/favorites/`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/favorites/` | List favorite vaults | Yes |
| POST | `/api/favorites/{vault_pk}/toggle/` | Add vault to favorites | Yes |
| DELETE | `/api/favorites/{vault_pk}/toggle/` | Remove vault from favorites | Yes |

---

## 🗄️ Database Schema

### Users Table
```sql
users
├── id (BigAutoField, PK)
├── email (EmailField, unique)
├── username (CharField)
├── bio (TextField, optional)
├── password (CharField - Django hashed)
├── is_active (BooleanField)
├── is_staff (BooleanField)
├── is_superuser (BooleanField)
├── created_at (DateTimeField)
└── updated_at (DateTimeField)
```

### Vaults Table
```sql
vaults
├── id (BigAutoField, PK)
├── name (CharField, 255)
├── category (CharField, 100)
├── owner_id (ForeignKey → users.id)
├── kdf_salt (TextField - base64 encoded)
├── encrypted_vault_key (TextField - base64 encoded)
├── biometric_enabled (BooleanField, default: False)
├── webauthn_credential_id (TextField, nullable)
├── webauthn_credential_public_key (TextField, nullable)
├── encrypted_vault_key_biometric (TextField, nullable)
├── created_at (DateTimeField)
└── updated_at (DateTimeField)
```

### Accounts Table
```sql
accounts
├── id (BigAutoField, PK)
├── vault_id (ForeignKey → vaults.id)
├── site_name (CharField, 255)
├── encrypted_password (TextField - base64 encoded)
├── iv_nonce (TextField - base64 encoded, 12 bytes)
├── password_strength (IntegerField, 0-100, nullable)
├── created_at (DateTimeField)
└── updated_at (DateTimeField)
```

### Categories Table
```sql
categories
├── id (BigAutoField, PK)
├── name (CharField, 100)
├── description (TextField, 500, optional)
├── user_id (ForeignKey → users.id)
├── created_at (DateTimeField)
└── updated_at (DateTimeField)
```

### Favorites Table
```sql
favorites
├── id (BigAutoField, PK)
├── user_id (ForeignKey → users.id)
├── vault_id (ForeignKey → vaults.id)
└── created_at (DateTimeField)

Constraints:
└── UNIQUE(user_id, vault_id)
```

---

## 🚢 Deployment

### Deploy to Render

1. **Push to GitHub**
```bash
git add .
git commit -m "Initial commit"
git push origin main
```

2. **Create Render Web Service**
   - Connect your GitHub repository
   - Set build command: `pip install -r requirements.txt && python manage.py migrate`
   - Set start command: `gunicorn password_manager.wsgi:application`
   - Add environment variables from `.env`

3. **Database Setup**
   - Create PostgreSQL database on Render
   - Set `DATABASE_URL` environment variable
   - Run migrations automatically or manually

4. **Configure CORS**
   - Add your frontend domain to `CORS_ALLOWED_ORIGINS`
   - Add to `CSRF_TRUSTED_ORIGINS`

### Environment Variables for Production

```env
DEBUG=False
SECRET_KEY=<generate-with-secrets-module>
DATABASE_URL=postgres://user:pass@host:5432/dbname
ALLOWED_HOSTS=your-domain.com,.onrender.com
CORS_ALLOWED_ORIGINS=https://your-frontend.com
CSRF_TRUSTED_ORIGINS=https://your-frontend.com,https://*.onrender.com
```

---

## 💻 Development

### Running Tests
```bash
python manage.py test
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints where applicable
- Document functions with docstrings
- Keep views focused on single responsibilities

### Adding New Features

1. **Create/update models** in respective app's `models.py`
2. **Run migrations**: `python manage.py makemigrations && python manage.py migrate`
3. **Create serializers** in `serializers.py`
4. **Implement views** in `views.py`
5. **Add URL routes** in `urls.py`
6. **Test endpoints** with Postman/Thunder Client

### Useful Commands

```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Access admin panel
python manage.py createsuperuser
# Then visit: http://localhost:8000/admin/

# Seed default categories
python manage.py seed_categories

# Run development server
python manage.py runserver

# Shell access
python manage.py shell
```

---

## 📝 API Usage Examples

### Register a New User
```bash
POST /api/users/register/
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "SecurePass123!",
  "bio": "Password manager user"
}

Response:
{
  "user": { "id": 1, "email": "user@example.com", "username": "johndoe" },
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

### Create a Vault
```bash
POST /api/vaults/
Headers: Authorization: Bearer <access_token>
{
  "name": "Personal Accounts",
  "category": "Personal",
  "master_password": "MyVaultPass123!"
}

Response:
{
  "id": 1,
  "name": "Personal Accounts",
  "category": "Personal",
  "biometric_enabled": false,
  "created_at": "2025-01-15T10:30:00Z"
}
```

### Unlock a Vault
```bash
POST /api/vaults/1/unlock/
Headers: Authorization: Bearer <access_token>
{
  "master_password": "MyVaultPass123!"
}

Response:
{
  "status": "success",
  "message": "Vault unlocked successfully.",
  "vault_id": 1,
  "vault_name": "Personal Accounts",
  "vault_key": "base64-encoded-vault-key"
}
```

### Generate a Password
```bash
POST /api/vaults/generate-password/
Headers: Authorization: Bearer <access_token>
{
  "length": 20,
  "use_lowercase": true,
  "use_uppercase": true,
  "use_digits": true,
  "use_special": true,
  "exclude_confusing": true,
  "mode": "password"
}

Response:
{
  "password": "Kj9#mN3$pL2@vX5&qR8!",
  "strength": {
    "score": 95,
    "label": "Very Strong",
    "feedback": []
  }
}
```

### Add Account to Vault
```bash
POST /api/vaults/1/accounts/
Headers: Authorization: Bearer <access_token>
{
  "site_name": "github.com",
  "encrypted_password": "base64-encrypted-password",
  "iv_nonce": "base64-iv-nonce"
}

Response:
{
  "id": 1,
  "site_name": "github.com",
  "password_strength": 88,
  "created_at": "2025-01-15T10:35:00Z"
}
```

---

## 🔐 Security Considerations

### For Production Use

1. **SECRET_KEY**
   - Use a cryptographically random key (50+ characters)
   - Never commit to version control
   - Rotate periodically

2. **Database**
   - Use strong database passwords
   - Enable SSL connections
   - Regular backups

3. **HTTPS**
   - Always use HTTPS in production
   - SSL redirect enforced automatically
   - HSTS enabled for 1 year

4. **JWT Tokens**
   - Access tokens expire in 30 minutes
   - Refresh tokens expire in 7 days
   - Tokens rotated on password change
   - Blacklisted on logout

5. **WebAuthn**
   - Requires HTTPS in production
   - Supports platform authenticators (Touch ID, Face ID, Windows Hello)
   - Supports roaming authenticators (YubiKey, etc.)

6. **Rate Limiting**
   - Consider adding rate limiting for auth endpoints
   - Implement account lockout after failed attempts

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Author

**Alex C.**
- GitHub: [@alecxander567](https://github.com/alecxander567)
- Project: [Password Manager App](https://github.com/alecxander567/Password-Manager-App)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📞 Support

For support, email support@example.com or open an issue on GitHub.

---

## 🎯 Roadmap

- [ ] Email verification for registration
- [ ] Two-factor authentication (TOTP)
- [ ] Password sharing with encryption
- [ ] Import/export vaults (encrypted)
- [ ] Password breach checking (HaveIBeenPwned API)
- [ ] Mobile app (React Native/Flutter)
- [ ] Browser extension
- [ ] Audit log for vault access
- [ ] Emergency access feature
- [ ] Dark web monitoring

---

## 🙏 Acknowledgments

- Django REST Framework for excellent API toolkit
- SimpleJWT for JWT authentication
- py_webauthn for WebAuthn implementation
- Cryptography library for secure encryption
- All contributors and testers

---

**Built with ❤️ for security and privacy**