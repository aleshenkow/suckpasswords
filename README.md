# SuckPasswords

A self-hosted corporate password vault with a web UI, LDAP/AD authentication, role-based access control, and AES-256-GCM encrypted storage.

## Features

- **HTTPS only** — nginx reverse proxy with TLS 1.2/1.3
- **LDAP / Active Directory** auth with group membership check and auto-provisioning
- **3-tier RBAC** — General, DomainAdmin, EnterpriseAdmin entry levels
- **Folder tree** with drag-and-drop organisation
- **Entry types** — Password, SSH, API token, with quick filter chips
- **Two vault layouts** — dense *Table* and *Split* (entry list + details panel); the choice is remembered per browser
- **Audited password reveal** — passwords are never sent in entry lists; showing or copying one goes through a dedicated endpoint and is written to the audit log
- **Password generator** and weak-password detection
- **AES-256-GCM** encryption for stored secrets (versioned scrypt-derived keys, legacy entries are re-encrypted automatically)
- **Encrypted backup / restore** (`.spbackup` files)
- **CSV import / export**
- **Inactivity auto-logout** after 5 minutes (disabled for "Remember me" sessions)
- **Remember me** option on login — keeps the session for 8 hours (`APP_REMEMBER_ME_EXPIRE_MINUTES`)
- **Account lockout** after 5 failed login attempts (unlocks after 15 min)
- **Brute-force rate limiting** on the login endpoint (nginx)
- **Audit log** of logins (success and failure) and password reveals
- **Daily database backups** — `pg_dump` kept for 14 days in `./backups`
- Dark / light theme, line-icon UI, `Ctrl/Cmd+K` to focus search

## Screenshots

Screenshots use generated demo data (no real credentials).

**Login**

![Login](docks/images/SuckLogin.png)

**Vault — Table layout, dark theme**

![Vault, table layout, dark theme](docks/images/SuckMain.png)

**Vault — Split layout (list + details)**

| Dark | Light |
|---|---|
| ![Split layout, dark](docks/images/SuckSplitDark.png) | ![Split layout, light](docks/images/SuckSplitLight.png) |

**Vault — Table layout, light theme**

![Vault, table layout, light theme](docks/images/SuckTableLight.png)

## Architecture

```
Browser → nginx :443 (HTTPS) → FastAPI :8000 → PostgreSQL
```

- **nginx** — TLS termination, security headers, rate limiting
- **backend** — FastAPI + SQLAlchemy 2.0, JWT (PyJWT) auth, bcrypt passwords, Alembic migrations; runs as a non-root user with a read-only filesystem and a healthcheck
- **db** — PostgreSQL 16
- **db-backup** — daily `pg_dump` (custom format) with 14-day retention

## Quick Start

### 1. Clone and enter the directory

```bash
git clone git@github.com:aleshenkow/suckpasswords.git
cd suckpasswords
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set strong values for at minimum:

| Variable | Description |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `APP_SECRET_KEY` | JWT signing key (32+ random chars); the app refuses to start with the default value |
| `APP_DATA_ENCRYPTION_KEY` | Entry encryption key (32+ random chars) |
| `APP_ADMIN_PASSWORD` | Initial admin password |

### 3. Generate a dev TLS certificate

```bash
cd certs && chmod +x generate-dev-cert.sh && ./generate-dev-cert.sh && cd ..
```

For production, replace `certs/server.crt` and `certs/server.key` with certificates from a trusted CA.

### 4. Start

```bash
docker compose up -d --build
```

Open **https://localhost** in your browser.

> The self-signed certificate will trigger a browser warning — accept it for local dev, use a real cert in production.

## Admin account

On **first startup**, the application creates the initial admin account using the credentials you provide in `.env`:

```dotenv
APP_ADMIN_USERNAME=your_admin_username
APP_ADMIN_PASSWORD=your_strong_admin_password
APP_ADMIN_EMAIL=admin@local       # optional
```

> If `APP_ADMIN_USERNAME` or `APP_ADMIN_PASSWORD` is empty and no admin user exists yet, the application will refuse to start with a clear error message.

Once the account is created the env variables are no longer used for login — you can clear them from `.env` if you prefer.

## Session lifetime

| Variable | Default | Description |
|---|---|---|
| `APP_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Token lifetime for a normal login |
| `APP_REMEMBER_ME_EXPIRE_MINUTES` | `480` | Token lifetime when "Remember me" is checked (8 h) |

With "Remember me" checked, the session survives page reloads and is not logged out by the 5-minute inactivity timer.

## LDAP / Active Directory

Set the following variables in `.env`:

```dotenv
AD_ENABLED=true
AD_SERVER_URI=ldaps://dc.example.local:636
AD_BASE_DN=DC=example,DC=local
AD_BIND_DN=CN=svc-bind,OU=ServiceAccounts,DC=example,DC=local
AD_BIND_PASSWORD=your_bind_password
AD_USER_FILTER=(sAMAccountName={username})
AD_REQUIRED_GROUP_DN=CN=VaultUsers,OU=Groups,DC=example,DC=local
```

Authentication flow:
1. If a local (`source=local`) user exists → local password check.
2. Otherwise → LDAP bind/search using the configured filter.
3. On success, a local profile is created automatically (if auto-provisioning is enabled).

LDAP settings can also be managed from the Admin → LDAP tab in the UI.

## Security notes for production

- Use certificates from a trusted CA (Let's Encrypt, internal PKI, etc.)
- Set strong, unique values for `APP_SECRET_KEY` and `APP_DATA_ENCRYPTION_KEY`
- Restrict access to port `443` via firewall or VPN
- Store `.env` outside the repository and never commit it
- Rotate secrets and backup encryption keys on a schedule
- Database dumps in `./backups` contain encrypted secrets, but keep the directory protected anyway
- Review backup files — they contain all vault entries encrypted with the backup password

## Project structure

```
suckpasswords/
├── docker-compose.yml
├── .env.example
├── .github/workflows/ci.yml   # ruff, pip-audit, image build
├── nginx/nginx.conf
├── certs/generate-dev-cert.sh
├── docks/images/              # README screenshots
└── backend/
    ├── Dockerfile
    ├── requirements.txt
    └── app/
        ├── main.py        # app setup, router wiring, UI serving
        ├── startup.py     # lifespan: migrations, admin bootstrap, legacy re-encryption
        ├── deps.py        # auth / admin dependencies
        ├── models.py      # SQLAlchemy models
        ├── schemas.py     # Pydantic schemas
        ├── security.py    # JWT, bcrypt, entry encryption
        ├── config.py      # settings from .env
        ├── database.py    # DB engine / session
        ├── routers/       # auth, folders, entries, admin, ldap, smtp, backup
        ├── services/      # access, audit, backup, folders, ldap, smtp
        ├── migrations/    # Alembic (baseline 0001)
        ├── ui.html        # single-page web UI shell
        └── static/        # ui.css, ui.js
```

## API

Interactive docs available at **https://localhost/docs** when the stack is running.

Key endpoints:

| Method | Path | Description |
|---|---|---|
| POST | `/auth/login` | Obtain JWT token |
| GET | `/users/me` | Current user info |
| GET/POST | `/folders` | List / create folders |
| GET/POST | `/entries` | List / create entries (list does not include passwords) |
| GET | `/entries/{id}/password` | Reveal a password (written to the audit log) |
| PUT/DELETE | `/entries/{id}` | Update / delete entry |
| GET | `/password/generate` | Generate a random password |
| POST | `/admin/backup` | Create encrypted backup |
| POST | `/admin/restore` | Restore from backup |
| GET | `/admin/users` | List users (admin) |
| POST | `/admin/ldap` | Save LDAP config (admin) |

## License

MIT
