# 👤 User APIs

<div align="center">

![Profile](https://img.shields.io/badge/Profile-Management-blue.svg) ![2FA](https://img.shields.io/badge/2FA-TOTP-green.svg) ![Security](https://img.shields.io/badge/Security-Enterprise-red.svg)

**Complete API reference for user profile management, security features, and session control**

</div>

---

## 📋 Table of Contents

- [👤 User APIs](#-user-apis)
  - [📋 Table of Contents](#-table-of-contents)
  - [👤 Profile Management](#-profile-management)
    - [Update Profile](#update-profile)
      - [📥 Request Body](#-request-body)
      - [📤 Response](#-response)
    - [Update Password](#update-password)
      - [📥 Request Body](#-request-body-1)
      - [📤 Response](#-response-1)
  - [🔒 Two-Factor Authentication](#-two-factor-authentication)
    - [Enable 2FA](#enable-2fa)
      - [📥 Request Body](#-request-body-2)
      - [📤 Response](#-response-2)
      - [📋 Response Fields](#-response-fields)
    - [Verify 2FA](#verify-2fa)
      - [📥 Request Body](#-request-body-3)
      - [📤 Response](#-response-3)
    - [Disable 2FA](#disable-2fa)
      - [📥 Request Body](#-request-body-4)
      - [📤 Response](#-response-4)
  - [📱 Session Management](#-session-management)
    - [Get Sessions](#get-sessions)
      - [📥 Request](#-request)
      - [📤 Response](#-response-5)
      - [📋 Session Object Fields](#-session-object-fields)
    - [Revoke Session](#revoke-session)
      - [📥 Request Body](#-request-body-5)
      - [📤 Response](#-response-6)
  - [🚨 Error Codes](#-error-codes)
  - [🔒 Security Notes](#-security-notes)

---

## 👤 Profile Management

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