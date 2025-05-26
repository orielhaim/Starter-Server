# 🔐 Authentication APIs

<div align="center">

![Authentication](https://img.shields.io/badge/Authentication-JWT-blue.svg) ![Security](https://img.shields.io/badge/Security-Enterprise-red.svg) ![2FA](https://img.shields.io/badge/2FA-TOTP-green.svg)

**Complete API reference for user authentication and session management**

</div>

---

## 📋 Table of Contents

- [Authentication](#-authentication)
  - [Register](#register)
  - [Login](#login)
  - [Refresh Token](#refresh-token)
  - [Logout](#logout)
  - [Get Profile](#get-profile)

---

## 🔐 Authentication

### Register

Create a new user account with email verification and automatic login.

**Endpoint:** `POST /auth/register`

**Authentication:** None required

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `email` | string | ✅ | Valid email format | User's email address |
| `password` | string | ✅ | Min 8 characters | User's password |
| `name` | string | ✅ | 3-50 characters | User's display name |

#### 📤 Response

**Success (201):**
```json
{
  "success": true,
  "user": {
    "id": 123,
    "email": "user@example.com",
    "name": "John Doe",
    "role": "user"
  },
  "sessionId": "sess_abc123def456"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "User already exists"
}
```

**Validation Error (400):**
```json
{
  "success": false,
  "errors": [
    {
      "field": "email",
      "message": "Invalid email"
    }
  ]
}
```

#### 🍪 Cookies Set

- `session_token` (HttpOnly, 1 hour)
- `refresh_token` (HttpOnly, 7 days)

---

### Login

Authenticate user with email and password, with optional 2FA support.

**Endpoint:** `POST /auth/login`

**Authentication:** None required

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `email` | string | ✅ | Valid email format | User's email address |
| `password` | string | ✅ | Not empty | User's password |
| `twoFactorToken` | string | ❌ | 6 digits | TOTP code from authenticator app |
| `backupCode` | string | ❌ | 8 characters | Backup code for 2FA |

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": 123,
    "name": "John Doe",
    "email": "user@example.com",
    "role": "user",
    "two_factor": "true",
    "created_at": "2024-01-01T00:00:00.000Z"
  },
  "sessionId": "sess_abc123def456"
}
```

**Error (401):**
```json
{
  "success": false,
  "error": "Invalid credentials"
}
```

**Banned User (403):**
```json
{
  "success": false,
  "error": "Account is suspended",
  "banExpiration": "2024-12-31T23:59:59.999Z"
}
```

#### 🍪 Cookies Set

- `session_token` (HttpOnly, 1 hour)
- `refresh_token` (HttpOnly, 7 days)

---

### Refresh Token

Refresh the session token using the refresh token.

**Endpoint:** `POST /auth/refresh`

**Authentication:** Refresh token (cookie)

#### 📥 Request Body

No body required. Uses refresh token from cookies.

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "user": {
    "id": 123,
    "name": "John Doe",
    "email": "user@example.com",
    "role": "user",
    "two_factor": "true",
    "created_at": "2024-01-01T00:00:00.000Z"
  }
}
```

**Error (401):**
```json
{
  "success": false,
  "error": "Invalid refresh token"
}
```

#### 🍪 Cookies Updated

- `session_token` (HttpOnly, 1 hour)
- `refresh_token` (HttpOnly, 7 days)

---

### Logout

Invalidate the current session and clear authentication cookies.

**Endpoint:** `POST /auth/logout`

**Authentication:** Session token (cookie)

#### 📥 Request Body

No body required.

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

#### 🍪 Cookies Cleared

- `session_token`
- `refresh_token`

---

### Get Profile

Retrieve the current user's profile information.

**Endpoint:** `GET /auth/me`

**Authentication:** Session token required

#### 📥 Request

No parameters required.

#### 📤 Response

**Success (200):**
```json
{
  "id": 123,
  "name": "John Doe",
  "email": "user@example.com",
  "role": "user",
  "two_factor": "true",
  "created_at": "2024-01-01T00:00:00.000Z",
  "updated_at": "2024-01-15T10:30:00.000Z"
}
```

---

## 🚨 Error Codes

| HTTP Status | Error Type | Description |
|-------------|------------|-------------|
| `400` | Bad Request | Invalid input data or validation errors |
| `401` | Unauthorized | Invalid credentials or expired session |
| `403` | Forbidden | Account suspended or insufficient permissions |
| `404` | Not Found | Resource not found |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server-side error |

## 🔒 Security Notes

- All endpoints use HTTPS in production
- Session tokens expire after 1 hour
- Refresh tokens expire after 7 days
- Rate limiting is applied to all authentication endpoints
- 2FA is strongly recommended for all accounts
- Backup codes should be stored securely and used only once
