/**
 * Enterprise Authentication System
 * Provides secure authentication with advanced features:
 * - Token management with automatic refresh
 * - Rate limiting and retry logic
 * - Comprehensive error handling
 * - Security headers and CSRF protection
 * - Performance optimizations with caching
 * - Event-driven architecture
 * - Audit logging
 */

class AuthError extends Error {
  constructor(message, code, statusCode = 500) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
    this.timestamp = new Date().toISOString();
  }
}

class RateLimiter {
  constructor(maxAttempts = 5, windowMs = 15 * 60 * 1000) { // 5 attempts per 15 minutes
    this.attempts = new Map();
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  isAllowed(key) {
    const now = Date.now();
    const attempts = this.attempts.get(key) || [];
    
    // Clean old attempts
    const validAttempts = attempts.filter(time => now - time < this.windowMs);
    this.attempts.set(key, validAttempts);
    
    return validAttempts.length < this.maxAttempts;
  }

  recordAttempt(key) {
    const attempts = this.attempts.get(key) || [];
    attempts.push(Date.now());
    this.attempts.set(key, attempts);
  }

  getRemainingTime(key) {
    const attempts = this.attempts.get(key) || [];
    if (attempts.length === 0) return 0;
    
    const oldestAttempt = Math.min(...attempts);
    const timeLeft = this.windowMs - (Date.now() - oldestAttempt);
    return Math.max(0, timeLeft);
  }
}

class TokenManager {
  constructor() {
    this.refreshPromise = null;
    this.refreshThreshold = 5 * 60 * 1000; // Refresh 5 minutes before expiry
  }

  shouldRefresh(tokenData) {
    if (!tokenData?.exp) return false;
    const expiryTime = tokenData.exp * 1000;
    const now = Date.now();
    return (expiryTime - now) <= this.refreshThreshold;
  }

  parseJWT(token) {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => 
        '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
      ).join(''));
      return JSON.parse(jsonPayload);
    } catch (error) {
      return null;
    }
  }
}

class SecurityManager {
  constructor() {
    this.csrfToken = null;
    this.deviceFingerprint = this.generateDeviceFingerprint();
  }

  generateDeviceFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprint', 2, 2);
    
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      canvas.toDataURL()
    ].join('|');
    
    return btoa(fingerprint).slice(0, 32);
  }

  async getCSRFToken() {
    if (!this.csrfToken) {
      try {
        const response = await fetch('/csrf-token', {
          method: 'GET',
          credentials: 'include'
        });
        const data = await response.json();
        this.csrfToken = data.csrfToken;
      } catch (error) {
        console.warn('Failed to get CSRF token:', error);
      }
    }
    return this.csrfToken;
  }

  getSecurityHeaders() {
    return {
      'X-Device-Fingerprint': this.deviceFingerprint,
      'X-Requested-With': 'XMLHttpRequest',
      'X-Client-Version': '1.0.0'
    };
  }
}

class EventEmitter {
  constructor() {
    this.events = {};
  }

  on(event, callback) {
    if (!this.events[event]) {
      this.events[event] = [];
    }
    this.events[event].push(callback);
  }

  emit(event, data) {
    if (this.events[event]) {
      this.events[event].forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error('Event callback error:', error);
        }
      });
    }
  }

  off(event, callback) {
    if (this.events[event]) {
      this.events[event] = this.events[event].filter(cb => cb !== callback);
    }
  }
}

class Auth extends EventEmitter {
  constructor(config = {}) {
    super();
    
    // Configuration
    this.config = {
      baseURL: config.baseURL || '',
      timeout: config.timeout || 30000,
      maxRetries: config.maxRetries || 3,
      retryDelay: config.retryDelay || 1000,
      enableLogging: config.enableLogging !== false,
      enableMetrics: config.enableMetrics !== false,
      ...config
    };

    // State management
    this.user = null;
    this.isAuthenticated = false;
    this.isLoading = false;
    this.lastActivity = Date.now();

    // Managers
    this.rateLimiter = new RateLimiter();
    this.tokenManager = new TokenManager();
    this.security = new SecurityManager();

    // Performance metrics
    this.metrics = {
      requests: 0,
      errors: 0,
      averageResponseTime: 0,
      lastRequestTime: 0
    };

    // Initialize
    this.init();
  }

  async init() {
    try {
      // Set up activity tracking
      this.setupActivityTracking();
      
      // Try to restore session
      await this.restoreSession();
      
      this.emit('initialized');
    } catch (error) {
      this.log('error', 'Initialization failed', error);
    }
  }

  setupActivityTracking() {
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
    const updateActivity = () => {
      this.lastActivity = Date.now();
    };

    events.forEach(event => {
      document.addEventListener(event, updateActivity, { passive: true });
    });

    // Check for inactivity every minute
    setInterval(() => {
      const inactiveTime = Date.now() - this.lastActivity;
      const maxInactiveTime = 30 * 60 * 1000; // 30 minutes

      if (inactiveTime > maxInactiveTime && this.isAuthenticated) {
        this.emit('inactivity-timeout');
        this.logout('inactivity');
      }
    }, 60000);
  }

  async restoreSession() {
    try {
      const user = await this.getUser(true);
      if (user && !user.error) {
        this.isAuthenticated = true;
        this.emit('session-restored', user);
      }
    } catch (error) {
      this.log('warn', 'Session restoration failed', error);
    }
  }

  log(level, message, data = null) {
    if (!this.config.enableLogging) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data,
      user: this.user?.id || 'anonymous'
    };

    console[level] || console.log(`[AUTH:${level.toUpperCase()}]`, message, data);
    
    // Send to logging service in production
    if (this.config.loggingEndpoint) {
      this.sendLog(logEntry);
    }
  }

  async sendLog(logEntry) {
    try {
      await fetch(this.config.loggingEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(logEntry)
      });
    } catch (error) {
      // Fail silently for logging
    }
  }

  updateMetrics(responseTime, isError = false) {
    if (!this.config.enableMetrics) return;

    this.metrics.requests++;
    if (isError) this.metrics.errors++;
    
    this.metrics.averageResponseTime = 
      (this.metrics.averageResponseTime * (this.metrics.requests - 1) + responseTime) / this.metrics.requests;
    
    this.metrics.lastRequestTime = Date.now();
  }

  async secureRequest(url, options = {}, retryCount = 0) {
    const startTime = Date.now();
    let response;

    try {
      // Validate URL
      if (!url) {
        throw new AuthError('URL is required', 'INVALID_URL', 400);
      }

      // Rate limiting
      const rateLimitKey = `${options.method || 'GET'}:${url}`;
      if (!this.rateLimiter.isAllowed(rateLimitKey)) {
        const remainingTime = this.rateLimiter.getRemainingTime(rateLimitKey);
        throw new AuthError(
          `Rate limit exceeded. Try again in ${Math.ceil(remainingTime / 1000)} seconds`,
          'RATE_LIMIT_EXCEEDED',
          429
        );
      }

      // Prepare headers
      const csrfToken = await this.security.getCSRFToken();
      const headers = {
        'Content-Type': 'application/json',
        ...this.security.getSecurityHeaders(),
        ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
        ...options.headers
      };

      // Make request with timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

      response = await fetch(`${this.config.baseURL}${url}`, {
        ...options,
        headers,
        credentials: 'include',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // Record attempt for rate limiting
      this.rateLimiter.recordAttempt(rateLimitKey);

      // Handle authentication errors
      if (response.status === 401 && retryCount === 0) {
        const refreshed = await this.refreshToken();
        if (refreshed) {
          return this.secureRequest(url, options, retryCount + 1);
        } else {
          this.emit('authentication-failed');
          throw new AuthError('Authentication failed', 'AUTH_FAILED', 401);
        }
      }

      // Handle other errors
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new AuthError(
          errorData.message || `HTTP ${response.status}`,
          errorData.code || 'HTTP_ERROR',
          response.status
        );
      }

      const responseTime = Date.now() - startTime;
      this.updateMetrics(responseTime, false);

      return response;

    } catch (error) {
      const responseTime = Date.now() - startTime;
      this.updateMetrics(responseTime, true);

      // Retry logic for network errors
      if (retryCount < this.config.maxRetries && 
          (error.name === 'TypeError' || error.name === 'AbortError')) {
        
        await new Promise(resolve => 
          setTimeout(resolve, this.config.retryDelay * Math.pow(2, retryCount))
        );
        
        return this.secureRequest(url, options, retryCount + 1);
      }

      this.log('error', 'Request failed', { url, error: error.message, retryCount });
      throw error;
    }
  }

  async getUser(force = false) {
    if (this.isLoading && !force) {
      return this.user;
    }

    if (!this.user || force) {
      this.isLoading = true;
      
      try {
        const response = await this.secureRequest('/api/auth/me');
        const userData = await response.json();
        
        this.user = userData;
        this.isAuthenticated = !userData.error;
        
        if (this.isAuthenticated) {
          this.emit('user-updated', userData);
        }
        
        this.log('info', 'User data fetched', { userId: userData.id });
        
      } catch (error) {
        this.log('error', 'Failed to fetch user', error);
        this.user = null;
        this.isAuthenticated = false;
        return null;
      } finally {
        this.isLoading = false;
      }
    }

    return this.user;
  }

  async refreshToken() {
    // Prevent multiple simultaneous refresh attempts
    if (this.tokenManager.refreshPromise) {
      return this.tokenManager.refreshPromise;
    }

    this.tokenManager.refreshPromise = this._performTokenRefresh();
    
    try {
      const result = await this.tokenManager.refreshPromise;
      return result;
    } finally {
      this.tokenManager.refreshPromise = null;
    }
  }

  async _performTokenRefresh() {
    try {
      this.log('info', 'Refreshing authentication token');
      
      const response = await this.secureRequest('/api/auth/refresh', {
        method: 'POST'
      });

      if (response.ok) {
        await this.getUser(true);
        this.emit('token-refreshed');
        this.log('info', 'Token refreshed successfully');
        return true;
      }

      this.log('warn', 'Token refresh failed');
      return false;

    } catch (error) {
      this.log('error', 'Token refresh error', error);
      this.emit('token-refresh-failed', error);
      return false;
    }
  }

  async login(credentials) {
    try {
      // Validate input
      const { email, password, twoFactorToken, backupCode, rememberMe } = credentials;
      
      if (!email || !password) {
        throw new AuthError('Email and password are required', 'MISSING_CREDENTIALS', 400);
      }

      // Email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        throw new AuthError('Invalid email format', 'INVALID_EMAIL', 400);
      }

      this.log('info', 'Login attempt', { email, has2FA: !!twoFactorToken });
      this.emit('login-attempt', { email });

      const body = { 
        email: email.toLowerCase().trim(), 
        password,
        deviceFingerprint: this.security.deviceFingerprint
      };
      
      if (twoFactorToken) body.twoFactorToken = twoFactorToken;
      if (backupCode) body.backupCode = backupCode;
      if (rememberMe) body.rememberMe = rememberMe;

      const response = await this.secureRequest('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(body)
      });

      const result = await response.json();

      if (response.ok) {
        await this.getUser(true);
        this.isAuthenticated = true;
        
        this.log('info', 'Login successful', { userId: this.user?.id });
        this.emit('login-success', this.user);
        
        return { success: true, user: this.user };
      }

      this.log('warn', 'Login failed', { email, reason: result.message });
      this.emit('login-failed', result);
      
      return { success: false, error: result };

    } catch (error) {
      this.log('error', 'Login error', error);
      this.emit('login-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code,
          statusCode: error.statusCode 
        } 
      };
    }
  }

  async logout(reason = 'user-initiated') {
    try {
      this.log('info', 'Logout initiated', { reason });
      this.emit('logout-attempt', { reason });

      const response = await this.secureRequest('/api/auth/logout', {
        method: 'POST'
      });

      if (response.ok) {
        this.user = null;
        this.isAuthenticated = false;
        this.security.csrfToken = null;
        
        this.log('info', 'Logout successful');
        this.emit('logout-success', { reason });
        
        return { success: true };
      }

      return { success: false, error: 'Logout failed' };

    } catch (error) {
      this.log('error', 'Logout error', error);
      this.emit('logout-error', error);
      
      // Clear local state even if server logout fails
      this.user = null;
      this.isAuthenticated = false;
      
      return { success: false, error: error.message };
    }
  }

  async register(userData) {
    try {
      const { email, password, confirmPassword, ...otherData } = userData;

      // Validation
      if (!email || !password || !confirmPassword) {
        throw new AuthError('All required fields must be provided', 'MISSING_FIELDS', 400);
      }

      if (password !== confirmPassword) {
        throw new AuthError('Passwords do not match', 'PASSWORD_MISMATCH', 400);
      }

      // Password strength validation
      if (password.length < 8) {
        throw new AuthError('Password must be at least 8 characters long', 'WEAK_PASSWORD', 400);
      }

      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
      if (!passwordRegex.test(password)) {
        throw new AuthError('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character', 'WEAK_PASSWORD', 400);
      }

      this.log('info', 'Registration attempt', { email });
      this.emit('register-attempt', { email });

      const body = {
        email: email.toLowerCase().trim(),
        password,
        deviceFingerprint: this.security.deviceFingerprint,
        ...otherData
      };

      const response = await this.secureRequest('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(body)
      });

      const result = await response.json();

      if (response.ok) {
        this.log('info', 'Registration successful', { email });
        this.emit('register-success', result);
        return { success: true, data: result };
      }

      this.log('warn', 'Registration failed', { email, reason: result.message });
      this.emit('register-failed', result);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', 'Registration error', error);
      this.emit('register-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code,
          statusCode: error.statusCode 
        } 
      };
    }
  }

  async changePassword(currentPassword, newPassword) {
    try {
      if (!currentPassword || !newPassword) {
        throw new AuthError('Current and new passwords are required', 'MISSING_PASSWORDS', 400);
      }

      if (newPassword.length < 8) {
        throw new AuthError('New password must be at least 8 characters long', 'WEAK_PASSWORD', 400);
      }

      // Validate password strength to match server requirements
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
      if (!passwordRegex.test(newPassword)) {
        throw new AuthError('New password must contain at least one lowercase letter, one uppercase letter, one number, and one special character', 'WEAK_PASSWORD', 400);
      }

      this.log('info', 'Password change attempt');
      this.emit('password-change-attempt');

      const response = await this.secureRequest('/api/user/change-password', {
        method: 'POST',
        body: JSON.stringify({
          currentPassword,
          newPassword,
          deviceFingerprint: this.security.deviceFingerprint
        })
      });

      const result = await response.json();

      if (response.ok) {
        this.log('info', 'Password changed successfully');
        this.emit('password-changed');
        return { success: true };
      }

      this.log('warn', 'Password change failed', result.message);
      this.emit('password-change-failed', result);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', 'Password change error', error);
      this.emit('password-change-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code 
        } 
      };
    }
  }

  async updateProfile(profileData) {
    try {
      const { name, ...otherData } = profileData;

      // Validation
      if (name && (name.length < 3 || name.length > 50)) {
        throw new AuthError('Name must be between 3 and 50 characters long', 'INVALID_NAME', 400);
      }

      this.log('info', 'Profile update attempt');
      this.emit('profile-update-attempt');

      const response = await this.secureRequest('/api/user/update', {
        method: 'POST',
        body: JSON.stringify({
          name,
          ...otherData
        })
      });

      const result = await response.json();

      if (response.ok) {
        // Update local user data
        this.user = { ...this.user, ...result };
        this.log('info', 'Profile updated successfully');
        this.emit('profile-updated', this.user);
        return { success: true, user: this.user };
      }

      this.log('warn', 'Profile update failed', result.message);
      this.emit('profile-update-failed', result);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', 'Profile update error', error);
      this.emit('profile-update-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code 
        } 
      };
    }
  }

  async enable2FA() {
    try {
      this.log('info', '2FA enable attempt');
      this.emit('2fa-enable-attempt');

      const response = await this.secureRequest('/api/user/enable-2fa', {
        method: 'POST'
      });

      const result = await response.json();

      if (response.ok) {
        this.log('info', '2FA enabled successfully');
        this.emit('2fa-enabled', result);
        return { success: true, data: result };
      }

      this.log('warn', '2FA enable failed', result.message);
      this.emit('2fa-enable-failed', result);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', '2FA enable error', error);
      this.emit('2fa-enable-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code 
        } 
      };
    }
  }

  async verify2FA(token) {
    try {
      if (!token || token.length !== 6) {
        throw new AuthError('Token must be 6 digits', 'INVALID_TOKEN', 400);
      }

      this.log('info', '2FA verification attempt');
      this.emit('2fa-verify-attempt');

      const response = await this.secureRequest('/api/user/verify-2fa', {
        method: 'POST',
        body: JSON.stringify({ token })
      });

      const result = await response.json();

      if (response.ok) {
        this.log('info', '2FA verified successfully');
        this.emit('2fa-verified', result);
        return { success: true, data: result };
      }

      this.log('warn', '2FA verification failed', result.message);
      this.emit('2fa-verify-failed', result);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', '2FA verification error', error);
      this.emit('2fa-verify-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code 
        } 
      };
    }
  }

  async disable2FA(token, backupCode) {
    try {
      if (!token && !backupCode) {
        throw new AuthError('Either token or backup code is required', 'MISSING_CREDENTIALS', 400);
      }

      if (token && token.length !== 6) {
        throw new AuthError('Token must be 6 digits', 'INVALID_TOKEN', 400);
      }

      if (backupCode && backupCode.length !== 8) {
        throw new AuthError('Backup code must be 8 characters', 'INVALID_BACKUP_CODE', 400);
      }

      this.log('info', '2FA disable attempt');
      this.emit('2fa-disable-attempt');

      const body = {};
      if (token) body.token = token;
      if (backupCode) body.backupCode = backupCode;

      const response = await this.secureRequest('/api/user/disable-2fa', {
        method: 'POST',
        body: JSON.stringify(body)
      });

      const result = await response.json();

      if (response.ok) {
        this.log('info', '2FA disabled successfully');
        this.emit('2fa-disabled', result);
        return { success: true, data: result };
      }

      this.log('warn', '2FA disable failed', result.message);
      this.emit('2fa-disable-failed', result);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', '2FA disable error', error);
      this.emit('2fa-disable-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code 
        } 
      };
    }
  }

  async getSessions() {
    try {
      this.log('info', 'Fetching user sessions');

      const response = await this.secureRequest('/api/user/sessions');
      const result = await response.json();

      if (response.ok) {
        this.log('info', 'Sessions fetched successfully');
        return { success: true, sessions: result };
      }

      this.log('warn', 'Failed to fetch sessions', result.message);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', 'Sessions fetch error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code 
        } 
      };
    }
  }

  async revokeSession(sessionId) {
    try {
      if (!sessionId) {
        throw new AuthError('Session ID is required', 'MISSING_SESSION_ID', 400);
      }

      this.log('info', 'Revoking session', { sessionId });
      this.emit('session-revoke-attempt', { sessionId });

      const response = await this.secureRequest('/api/user/revoke-session', {
        method: 'POST',
        body: JSON.stringify({ sessionId })
      });

      const result = await response.json();

      if (response.ok) {
        this.log('info', 'Session revoked successfully', { sessionId });
        this.emit('session-revoked', { sessionId });
        return { success: true };
      }

      this.log('warn', 'Session revoke failed', result.message);
      this.emit('session-revoke-failed', result);
      return { success: false, error: result };

    } catch (error) {
      this.log('error', 'Session revoke error', error);
      this.emit('session-revoke-error', error);
      
      return { 
        success: false, 
        error: { 
          message: error.message, 
          code: error.code 
        } 
      };
    }
  }

  // Utility methods
  isLoggedIn() {
    return this.isAuthenticated && this.user && !this.user.error;
  }

  hasRole(role) {
    return this.user?.roles?.includes(role) || false;
  }

  hasPermission(permission) {
    return this.user?.permissions?.includes(permission) || false;
  }

  getMetrics() {
    return { ...this.metrics };
  }

  // Cleanup method
  destroy() {
    this.events = {};
    this.user = null;
    this.isAuthenticated = false;
    this.tokenManager.refreshPromise = null;
  }
}

// Create singleton instance
const auth = new Auth({
  enableLogging: true,
  enableMetrics: true,
  timeout: 30000,
  maxRetries: 3
});

// Global error handler
window.addEventListener('unhandledrejection', (event) => {
  if (event.reason instanceof AuthError) {
    auth.log('error', 'Unhandled auth error', event.reason);
    event.preventDefault();
  }
});

// Export for global use
if (typeof window !== 'undefined') {
  window.auth = auth;
  window.AuthError = AuthError;
}