import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

// Prevent token refresh race conditions
let isRefreshing = false;
let refreshSubscribers = [];

// GET-only request deduplication (auto-cleaned)
const pendingGets = new Map();

const api = axios.create({
  baseURL: API_URL,
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
  timeout: 30000,
});

// ============================================================================
// CSRF Token Management
// In cross-origin setups (frontend :5173 ↔ backend :8000), JavaScript can't
// read cookies set by the API origin. We fetch the token from the /csrf/
// endpoint's JSON body and attach it as a header on every mutating request.
// ============================================================================
let _csrfToken = null;
let _csrfPromise = null;

function fetchCsrfToken() {
  if (!_csrfPromise) {
    _csrfPromise = axios
      .get(`${API_URL}/auth/csrf/`, { withCredentials: true })
      .then(({ data }) => {
        _csrfToken = data.csrfToken;
      })
      .catch(() => {
        _csrfPromise = null; // Allow retry on next attempt
      });
  }
  return _csrfPromise;
}

/** Clear cached CSRF token (call on logout so the next POST lazily fetches a fresh one) */
export function clearCsrfToken() {
  _csrfToken = null;
  _csrfPromise = null;
}

const subscribeTokenRefresh = (cb) => refreshSubscribers.push(cb);

const onTokenRefreshed = () => {
  refreshSubscribers.forEach((cb) => cb());
  refreshSubscribers = [];
};

/**
 * Extract a safe, user-friendly error message from an API error.
 * Backend error messages are trusted (they are already sanitized server-side).
 */
export function getErrorMessage(error) {
  if (!error.response || error.code === "ECONNABORTED") {
    return "Connection timeout. Please check your internet connection.";
  }

  const { status, data } = error.response;
  const serverMsg = data?.error;

  if (status === 401) return serverMsg || "Authentication failed";
  if (status === 403) return "Access denied";
  if (status === 404) return "Resource not found";
  if (status === 429) return "Too many requests. Please try again later.";
  if (status >= 500) return "Server error. Please try again later.";

  return serverMsg || "An error occurred. Please try again.";
}

// Public endpoints that never trigger a token refresh
const PUBLIC_ENDPOINTS = [
  "/auth/login/",
  "/auth/register/",
  "/auth/google/login/",
  "/auth/password/reset/request/",
  "/auth/password/reset/verify/",
  "/auth/verify-email-otp/",
  "/auth/resend-verification/",
  "/auth/csrf/",
  "/auth/mfa/verify/",
  "/auth/me/",
  "/auth/token/refresh/",
];

// Response interceptor — silent 401 handling + automatic token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;

    // Silent 401 for initial auth check (don't show error)
    if (error.response?.status === 401 && original.url?.includes("/auth/me/")) {
      return Promise.reject({ ...error, silent: true });
    }

    const isPublic = PUBLIC_ENDPOINTS.some((ep) => original.url?.includes(ep));

    // Auto-refresh token on 401 for protected endpoints
    if (error.response?.status === 401 && !original._retry && !isPublic) {
      original._retry = true;

      if (isRefreshing) {
        return new Promise((resolve) => {
          subscribeTokenRefresh(() => resolve(api(original)));
        });
      }

      isRefreshing = true;

      try {
        await axios.post(
          `${API_URL}/auth/token/refresh/`,
          {},
          { withCredentials: true },
        );
        isRefreshing = false;
        onTokenRefreshed();
        return api(original);
      } catch {
        isRefreshing = false;
        refreshSubscribers = [];

        // Redirect to login (only if not already on a public page)
        if (
          !/\/(login|register|forgot-password|verify-email)/.test(
            window.location.pathname,
          )
        ) {
          window.dispatchEvent(new CustomEvent("auth:logout"));
        }

        return Promise.reject({ ...error, silent: true });
      }
    }

    return Promise.reject(error);
  },
);

// Request interceptor — CSRF header + GET deduplication
api.interceptors.request.use(
  async (config) => {
    // Attach CSRF token to all mutating requests (POST, PUT, PATCH, DELETE)
    if (config.method !== "get") {
      if (!_csrfToken) await fetchCsrfToken();
      if (_csrfToken) config.headers["X-CSRFToken"] = _csrfToken;
    }

    // Deduplicate concurrent GET requests
    if (config.method === "get") {
      const key = config.url;
      if (pendingGets.has(key)) {
        pendingGets.get(key).abort();
      }
      const controller = new AbortController();
      config.signal = controller.signal;
      pendingGets.set(key, controller);
    }
    return config;
  },
  (error) => Promise.reject(error),
);

// Clean up completed GETs from the map
api.interceptors.response.use(
  (response) => {
    if (response.config.method === "get") {
      pendingGets.delete(response.config.url);
    }
    return response;
  },
  (error) => {
    if (error.config?.method === "get") {
      pendingGets.delete(error.config.url);
    }
    return Promise.reject(error);
  },
);

// Input validation (lightweight client-side guard; backend is source of truth)
const validate = (data, rules) => {
  const errors = {};
  for (const [field, rule] of Object.entries(rules)) {
    const val = data[field];
    if (rule.required && !val) errors[field] = `${field} is required`;
    else if (rule.minLength && val?.length < rule.minLength)
      errors[field] = `${field} must be at least ${rule.minLength} characters`;
    else if (rule.maxLength && val?.length > rule.maxLength)
      errors[field] = `${field} must be less than ${rule.maxLength} characters`;
    else if (rule.pattern && val && !rule.pattern.test(val))
      errors[field] = `${field} format is invalid`;
  }
  return Object.keys(errors).length ? errors : null;
};

const reject = (errors) => Promise.reject({ response: { data: errors } });

// Validated API methods
export const authAPI = {
  register: (data) => {
    const errors = validate(data, {
      username: { required: true, minLength: 3, maxLength: 150 },
      email: { required: true, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
      password: { required: true, minLength: 8, maxLength: 128 },
    });
    return errors ? reject(errors) : api.post("/auth/register/", data);
  },

  login: (data) => {
    const errors = validate(data, {
      email: { required: true },
      password: { required: true },
    });
    return errors ? reject(errors) : api.post("/auth/login/", data);
  },

  googleLogin: (token) => {
    if (!token || typeof token !== "string")
      return reject({ error: "Invalid token" });
    return api.post("/auth/google/login/", { token });
  },

  logout: () => api.post("/auth/logout/", {}),
  getCurrentUser: () => api.get("/auth/me/"),

  verifyEmailOTP: (data) => {
    const errors = validate(data, {
      email: { required: true },
      code: { required: true, minLength: 6, maxLength: 6 },
    });
    return errors ? reject(errors) : api.post("/auth/verify-email-otp/", data);
  },

  resendVerification: (data) => api.post("/auth/resend-verification/", data),
  changePassword: (data) => api.post("/auth/password/change/", data),
  requestPasswordReset: (data) =>
    api.post("/auth/password/reset/request/", data),
  verifyPasswordReset: (data) => api.post("/auth/password/reset/verify/", data),

  // MFA endpoints
  mfaSetup: () => api.post("/auth/mfa/setup/", {}),
  mfaEnable: (data) => api.post("/auth/mfa/enable/", data),
  mfaDisable: (data) => api.post("/auth/mfa/disable/", data),
  mfaVerifyLogin: (data) => {
    const errors = validate(data, {
      mfa_token: { required: true },
      mfa_code: { required: true, minLength: 6, maxLength: 6 },
    });
    return errors ? reject(errors) : api.post("/auth/mfa/verify/", data);
  },
};

/** Cancel all pending GET requests (call on unmount/logout) */
export const cancelPendingRequests = () => {
  pendingGets.forEach((controller) => controller.abort());
  pendingGets.clear();
};

export default api;
