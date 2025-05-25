# 👤 User APIs

<div align="center">

![Authentication](https://img.shields.io/badge/Authentication-JWT-blue.svg) ![2FA](https://img.shields.io/badge/2FA-TOTP-green.svg) ![Security](https://img.shields.io/badge/Security-Enterprise-red.svg)

**Complete API reference for user authentication, profile management, and security features**

</div>

---

## 📋 Table of Contents

- [Authentication](#-authentication)
  - [Register](#register)
  - [Login](#login)
  - [Refresh Token](#refresh-token)
  - [Logout](#logout)
- [Profile Management](#-profile-management)
  - [Get Profile](#get-profile)
  - [Update Profile](#update-profile)
  - [Update Password](#update-password)
- [Two-Factor Authentication](#-two-factor-authentication)
  - [Enable 2FA](#enable-2fa)
  - [Verify 2FA](#verify-2fa)
  - [Disable 2FA](#disable-2fa)
- [Session Management](#-session-management)
  - [Get Sessions](#get-sessions)
  - [Revoke Session](#revoke-session)

---

## 🔐 Authentication

### Register

Create a new user account with email verification and automatic login.

**Endpoint:** `POST /user/register`

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

**Endpoint:** `POST /user/login`

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

**Endpoint:** `POST /user/refresh`

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

**Endpoint:** `POST /user/logout`

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

## 👤 Profile Management

### Get Profile

Retrieve the current user's profile information.

**Endpoint:** `GET /user/me`

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

### Update Profile

Update user profile information with 2FA verification.

**Endpoint:** `POST /user/update`

**Authentication:** Session token required + 2FA verification

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `name` | string | ❌ | 3-50 characters | New display name |
| `twoFactorToken` | string | ⚠️* | 6 digits | TOTP code (required if 2FA enabled) |
| `backupCode` | string | ⚠️* | 8 characters | Backup code (alternative to TOTP) |

*Required if user has 2FA enabled

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "user": {
    "id": 123,
    "name": "John Smith",
    "email": "user@example.com",
    "role": "user"
  }
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Invalid two-factor token"
}
```

---

### Update Password

Change user password with current password verification and 2FA.

**Endpoint:** `POST /user/update-password`

**Authentication:** Session token required + 2FA verification

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `currentPassword` | string | ✅ | Not empty | Current password |
| `newPassword` | string | ✅ | Complex password* | New password |
| `twoFactorToken` | string | ⚠️** | 6 digits | TOTP code |
| `backupCode` | string | ⚠️** | 8 characters | Backup code |

*Password Requirements:
- 8-128 characters
- At least one lowercase letter
- At least one uppercase letter  
- At least one number
- At least one special character (@$!%*?&)

**Required if user has 2FA enabled

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Password updated successfully"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Current password is incorrect"
}
```

---

## 🔒 Two-Factor Authentication

### Enable 2FA

Initialize two-factor authentication setup for the user account.

**Endpoint:** `POST /user/enable-2fa`

**Authentication:** Session token required

#### 📥 Request Body

No body required.

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Two-factor authentication setup initiated",
  "qrCode": "data:image/png;base64,...",
  "manualEntryKey": "............",
  "backupCodes": [
    "........"
  ]
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Two-factor authentication is already enabled"
}
```

#### 📋 Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `qrCode` | string | Base64 encoded QR code image for authenticator apps |
| `manualEntryKey` | string | Secret key for manual entry in authenticator apps |
| `backupCodes` | array | One-time use backup codes (store securely) |

---

### Verify 2FA

Complete 2FA setup by verifying a TOTP token.

**Endpoint:** `POST /user/verify-2fa`

**Authentication:** Session token required

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `token` | string | ✅ | 6 digits | TOTP code from authenticator app |

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Two-factor authentication enabled successfully"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Invalid verification token"
}
```

---

### Disable 2FA

Disable two-factor authentication for the user account.

**Endpoint:** `POST /user/disable-2fa`

**Authentication:** Session token required

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `token` | string | ❌* | 6 digits | TOTP code from authenticator app |
| `backupCode` | string | ❌* | 8 characters | Backup code |

*One of `token` or `backupCode` is required

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Two-factor authentication disabled successfully"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Invalid token or backup code"
}
```

---

## 📱 Session Management

### Get Sessions

Retrieve all active sessions for the current user.

**Endpoint:** `GET /user/sessions`

**Authentication:** Session token required

#### 📥 Request

No parameters required.

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "sessions": [
    {
      "sessionId": "sess_abc123def456",
      "ip": "192.168.1.100",
      "browser": "Chrome",
      "os": "Windows",
      "device": "desktop",
      "lastActivity": "2024-01-15T10:30:00.000Z",
      "createdAt": "2024-01-15T09:00:00.000Z",
      "isCurrent": true
    },
    ....
  ],
  "totalSessions": 2
}
```

#### 📋 Session Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `sessionId` | string | Unique session identifier |
| `ip` | string | IP address of the session |
| `browser` | string | Browser name |
| `os` | string | Operating system |
| `device` | string | Device type (desktop/mobile/tablet) |
| `lastActivity` | string | ISO timestamp of last activity |
| `createdAt` | string | ISO timestamp of session creation |
| `isCurrent` | boolean | Whether this is the current session |

---

### Revoke Session

Terminate a specific session by session ID.

**Endpoint:** `POST /user/revoke-session`

**Authentication:** Session token required

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `sessionId` | string | ✅ | Not empty | Session ID to terminate |

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "message": "Session revoked successfully"
}
```

**Error (404):**
```json
{
  "success": false,
  "error": "Session not found"
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