# SuckPasswords

Self-hosted хранилище паролей с поддержкой:
- Docker Compose
- HTTPS через NGINX (порт 8888)
- авторизации через LDAP/AD с фильтрацией по группе
- иерархии папок
- записей с полями: title, login, password, url, description
- генератора паролей
- ролей и гибких прав на чтение/запись по типам записей
- встроенного администратора `suckadmin`

## Архитектура

- `nginx`:
  - принимает HTTPS трафик на `:8888`
  - проксирует в backend
- `backend`:
  - FastAPI API + OpenAPI UI (`/docs`)
  - JWT auth
  - LDAP/AD auth (опционально)
  - RBAC
- `db`:
  - PostgreSQL

## Быстрый старт

1. Перейдите в каталог проекта:

```bash
cd /Users/a.aleschenkow/SuckPasswords/GitHub/suckpasswords
```

2. Подготовьте окружение:

```bash
cp .env.example .env
```

3. Сгенерируйте dev TLS-сертификаты:

```bash
cd certs
chmod +x generate-dev-cert.sh
./generate-dev-cert.sh
cd ..
```

4. Запустите стек:

```bash
docker compose up -d --build
```

5. Откройте веб-интерфейс API:

- https://localhost:8888/docs

## Дефолтный админ

Создается автоматически при первом старте backend:
- username: `suckadmin`
- password: `suckpassword`

Важно: сразу смените пароль в продакшене.

## LDAP/AD

Настройте параметры в `.env`:
- `AD_ENABLED=true`
- `AD_SERVER_URI=ldaps://...`
- `AD_BASE_DN=...`
- `AD_BIND_DN=...`
- `AD_BIND_PASSWORD=...`
- `AD_USER_FILTER=(sAMAccountName={username})`
- `AD_REQUIRED_GROUP_DN=...`

Логин:
- Если найден локальный пользователь `source=local`, проверяется локальный пароль.
- Иначе выполняется bind/check в AD.
- Если AD-пользователь успешно аутентифицирован, локальный профиль создается автоматически.

## Основные API

### 1) Логин

`POST /auth/login`

```json
{
  "username": "suckadmin",
  "password": "suckpassword"
}
```

Ответ содержит `access_token`.

### 2) Текущий пользователь

`GET /users/me`

Нужен Bearer token.

### 3) Папки

- `POST /folders`
- `GET /folders`

### 4) Записи

- `POST /entries`
- `GET /entries`

Поля записи:
- `title`
- `login`
- `password`
- `url`
- `description`

### 5) Генератор паролей

`GET /password/generate?length=24`

### 6) Роли и права (admin)

- `POST /admin/roles`
- `POST /admin/permissions`
- `POST /admin/roles/assign`

Права задаются на тип записи (`entry_type_code`) с флагами:
- `can_read`
- `can_write`

## Безопасность

Реализовано:
- HTTPS only через NGINX
- TLS 1.2/1.3
- Security headers
- JWT auth
- bcrypt для паролей пользователей
- шифрование паролей записей на уровне приложения

Рекомендации для продакшена:
- использовать сертификаты от доверенного CA
- сменить `APP_SECRET_KEY`, `APP_DATA_ENCRYPTION_KEY`, все пароли в `.env`
- убрать дефолтный пароль admin
- ограничить доступ к `:8888` firewall/VPN
- добавить аудит-логирование, ротацию ключей и бэкапы

## Структура проекта

- `docker-compose.yml`
- `nginx/nginx.conf`
- `certs/generate-dev-cert.sh`
- `backend/Dockerfile`
- `backend/requirements.txt`
- `backend/app/main.py`
- `backend/app/models.py`
- `backend/app/security.py`
- `backend/app/config.py`
- `backend/app/database.py`
- `backend/app/schemas.py`
