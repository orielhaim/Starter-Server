# 👑 Admin APIs

<div align="center">

![Admin](https://img.shields.io/badge/Admin-Only-red.svg) ![RBAC](https://img.shields.io/badge/RBAC-Enabled-orange.svg) ![Security](https://img.shields.io/badge/Security-Enterprise-red.svg)

**Administrative API reference for user management, system administration, and security operations**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Authentication & Permissions](#-authentication--permissions)
- [User Management](#-user-management)
  - [Get All Users](#get-all-users)
  - [Get User Details](#get-user-details)
  - [Ban User](#ban-user)

---

## 🔍 Overview

The Admin APIs provide comprehensive administrative functionality for managing users, monitoring system activity, and performing security operations. All admin endpoints require specific permissions and are protected by role-based access control (RBAC).

### 🛡️ Security Features

- **Role-based Access Control (RBAC)** - Granular permission system
- **Audit Logging** - All admin actions are logged with full context
- **Session Tracking** - Monitor admin sessions and activities
- **Rate Limiting** - Enhanced rate limiting for admin operations

---

## 🔐 Authentication & Permissions

All admin endpoints require:

1. **Valid Session Token** - Active admin session
2. **Required Permissions** - Specific permissions for each operation
3. **Admin Role** - User must have admin-level access

### 📋 Permission Types

| Permission | Description | Required For |
|------------|-------------|--------------|
| `readUsers` | View user information and lists | All user read operations |
| `banUser` | Ban/suspend user accounts | User moderation actions |
| `manageUsers` | Full user management capabilities | User CRUD operations |
| `*` | System-level administration | System configuration |

### 🔑 Authentication Header

Session cookies:
```http
Cookie: session_token=<token>
```

---

## 👥 User Management

### Get All Users

Retrieve a list of all users in the system with their basic information.

**Endpoint:** `GET /admin/users`

**Authentication:** Session token required

**Required Permissions:** `readUsers`

#### 📥 Request

No parameters required.

#### 📤 Response

**Success (200):**
```json
[
  {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "user",
    "two_factor": "true",
    "ban": 0,
    "created_at": "2024-01-01T00:00:00.000Z",
    "updated_at": "2024-01-15T10:30:00.000Z",
    "register_data": "{\"ip\":\"192.168.1.100\",\"userAgent\":{\"browser\":{\"name\":\"Chrome\"}}}"
  },
  ....
]
```

**Error (403):**
```json
{
  "success": false,
  "error": "Insufficient permissions"
}
```

**Error (500):**
```json
{
  "error": "Failed to get users"
}
```

#### 📋 User Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique user identifier |
| `name` | string | User's display name |
| `email` | string | User's email address |
| `role` | string | User role (user/admin/moderator) |
| `two_factor` | string | 2FA status ("true"/"false") |
| `ban` | integer | Ban expiration timestamp (0 = not banned) |
| `created_at` | string | ISO timestamp of account creation |
| `updated_at` | string | ISO timestamp of last update |
| `register_data` | string | JSON string with registration metadata |

---

### Get User Details

Retrieve detailed information about a specific user, including their sessions.

**Endpoint:** `GET /admin/user/:userId`

**Authentication:** Session token required

**Required Permissions:** `readUsers`

#### 📥 Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `userId` | integer | ✅ | User ID to retrieve |

#### 📤 Response

**Success (200):**
```json
{
  "success": true,
  "user": {
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "user",
    "two_factor": "true",
    "two_factor_secret": "JBSWY3DPEHPK3PXP",
    "ban": 0,
    "created_at": "2024-01-01T00:00:00.000Z",
    "updated_at": "2024-01-15T10:30:00.000Z",
    "register_data": "{\"ip\":\"192.168.1.100\",\"userAgent\":{\"browser\":{\"name\":\"Chrome\",\"version\":\"120.0.0.0\"},\"os\":{\"name\":\"Windows\",\"version\":\"10\"}},\"backupCodes\":[\"12345678\",\"87654321\"]}"
  },
  "sessions": [
    {
      "session_id": "sess_abc123def456",
      "user_id": 123,
      "ip": "192.168.1.100",
      "user_agent": "{\"browser\":{\"name\":\"Chrome\",\"version\":\"120.0.0.0\"},\"os\":{\"name\":\"Windows\",\"version\":\"10\"}}",
      "active": "true",
      "last_activity": "2024-01-15T10:30:00.000Z",
      "created_at": "2024-01-15T09:00:00.000Z"
    },
    ....
  ]
}
```

**Validation Error (400):**
```json
{
  "success": false,
  "message": "Validation error",
  "errors": [
    {
      "field": "userId",
      "message": "User ID must be an integer"
    }
  ]
}
```

**User Not Found (404):**
```json
{
  "success": false,
  "message": "User not found",
  "code": "USER_NOT_FOUND"
}
```

**Error (500):**
```json
{
  "success": false,
  "message": "Internal server error",
  "error": "Database connection failed"
}
```

#### 📋 Extended User Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `two_factor_secret` | string | 2FA secret key (admin only) |
| `register_data` | object | Parsed registration metadata including backup codes |

#### 📋 Session Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Unique session identifier |
| `user_id` | integer | Associated user ID |
| `ip` | string | IP address of the session |
| `user_agent` | string | JSON string with browser/OS information |
| `active` | string | Session status ("true"/"false") |
| `last_activity` | string | ISO timestamp of last activity |
| `created_at` | string | ISO timestamp of session creation |

---

### Ban User

Suspend a user account for a specified duration with an optional reason.

**Endpoint:** `POST /admin/banUser`

**Authentication:** Session token required

**Required Permissions:** `readUsers`, `banUser`

#### 📥 Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `userId` | integer | ✅ | Must be valid integer | User ID to ban |
| `duration` | integer | ✅ | Must be positive integer | Ban duration in seconds |
| `reason` | string | ❌ | String | Reason for the ban |

#### 📤 Response

**Success (200):**
```json
{
  "success": true
}
```

**Validation Error (400):**
```json
{
  "success": false,
  "message": "Validation error",
  "errors": [
    {
      "field": "userId",
      "message": "User ID must be an integer"
    },
    {
      "field": "duration",
      "message": "Duration must be an integer"
    }
  ]
}
```

**User Not Found (404):**
```json
{
  "success": false,
  "message": "User not found",
  "code": "USER_NOT_FOUND"
}
```

**Permission Error (403):**
```json
{
  "success": false,
  "message": "You do not have permission to change this user's ban status"
}
```

**Invalid Duration (400):**
```json
{
  "success": false,
  "message": "Duration must be greater than current time or 0"
}
```

**Error (500):**
```json
{
  "success": false,
  "message": "Internal server error"
}
```

#### ⏰ Duration Examples

| Duration (seconds) | Human Readable |
|-------------------|----------------|
| `3600` | 1 hour |
| `86400` | 1 day |
| `604800` | 1 week |
| `2592000` | 30 days |
| `31536000` | 1 year |

---

## 🚨 Error Codes

| HTTP Status | Error Type | Description |
|-------------|------------|-------------|
| `400` | Bad Request | Invalid input data or validation errors |
| `401` | Unauthorized | Invalid session or expired token |
| `403` | Forbidden | Insufficient permissions for the operation |
| `404` | Not Found | Requested resource not found |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server-side error |

## 🔒 Security Considerations

### 🛡️ Access Control

- All admin operations require explicit permissions
- Permission checks are performed on every request
- Admin actions are logged with full audit trail
- Session validation includes permission verification

### 📊 Audit Logging

All admin operations are automatically logged with:

- **Admin User ID** - Who performed the action
- **Target User ID** - Who was affected (if applicable)
- **Action Type** - What operation was performed
- **Timestamp** - When the action occurred
- **IP Address** - Where the action originated
- **Request Details** - Full request context

### 🚨 Rate Limiting

Admin endpoints have enhanced rate limiting:

- **Standard Operations:** 100 requests per minute
- **Sensitive Operations:** 20 requests per minute
- **Ban Operations:** 10 requests per minute

### 🔐 Data Protection

- Sensitive user data is only accessible with proper permissions
- 2FA secrets are only visible to users with `systemAdmin` permission
- Password hashes are never returned in API responses
- Session tokens are handled securely