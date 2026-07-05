const allowedBaseDomain = String(process.env.ALLOWED_BASE_DOMAIN || '')
  .trim()
  .toLowerCase();
const configuredOrigins = String(process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const allowedOrigins = new Set(configuredOrigins);

function isDevLocalhost(originUrl) {
  const host = String(originUrl.hostname || '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1';
}

function isAllowedByBaseDomain(originUrl) {
  if (!allowedBaseDomain) {
    return false;
  }

  const host = String(originUrl.hostname || '').toLowerCase();
  return host === allowedBaseDomain || host.endsWith(`.${allowedBaseDomain}`);
}

module.exports = {
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200,
  origin: (origin, callback) => {
    // Allow requests without Origin header (server-to-server, curl, health checks).
    if (!origin) {
      callback(null, true);
      return;
    }

    try {
      const originUrl = new URL(origin);
      const isDevelopment = process.env.NODE_ENV !== 'production';

      if (allowedOrigins.has(origin) || isAllowedByBaseDomain(originUrl)) {
        callback(null, true);
        return;
      }

      if (isDevelopment && isDevLocalhost(originUrl)) {
        callback(null, true);
        return;
      }

      callback(new Error(`Not allowed by CORS: ${origin}`));
    } catch {
      callback(new Error(`Invalid Origin header: ${origin}`));
    }
  },
};
