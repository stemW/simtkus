
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { Readable } = require("stream");
const { google } = require("googleapis");
const {
  ListObjectsV2Command,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
} = require("@aws-sdk/client-s3");
const {
  Route53Client,
  ListResourceRecordSetsCommand,
  ChangeResourceRecordSetsCommand,
} = require("@aws-sdk/client-route-53");
const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");
const crypto = require("crypto");
const https = require("https");
const upnp = require("nat-upnp");
const {
  S3UploadError,
  uploadFile,
  uploadMultipleFiles,
  deleteFile,
  generatePresignedUploadUrl,
  generatePresignedDownloadUrl,
} = require("./services/aws/s3UploadService");
const { createS3Client } = require("./services/aws/s3Client");
require('dotenv').config();
const PUBLIC_DIR = __dirname;
const PRIVATE_DIR = path.join(__dirname, '..', 'github_private');
const PRIVATE_ENV_PATH = path.join(PRIVATE_DIR, '.env');
const PRIVATE_FALLBACK_ENV_PATHS = [
  path.join(PRIVATE_DIR, 'simtkus_env.txt'),
  path.join(PRIVATE_DIR, 'smarkwm_env.txt'),
];

try {
  if (fs.existsSync(PRIVATE_ENV_PATH)) {
    require('dotenv').config({ path: PRIVATE_ENV_PATH });
    console.log('Loaded env from', PRIVATE_ENV_PATH);
  }
} catch (e) {
  console.warn('Failed to load private .env file', e && e.message);
}
// Keep env naming backward-compatible across old and new S3 implementations.
if (!process.env.AWS_S3_BUCKET && process.env.S3_BUCKET_NAME) {
  process.env.AWS_S3_BUCKET = process.env.S3_BUCKET_NAME;
}
if (!process.env.S3_BUCKET_NAME && process.env.AWS_S3_BUCKET) {
  process.env.S3_BUCKET_NAME = process.env.AWS_S3_BUCKET;
}
// Backward-compat: if .env is not present but an env fallback file exists,
// load KEY=VALUE lines into process.env so server features (S3, AWS) work without manual copying.
try {
  const fallbackEnvPath = PRIVATE_FALLBACK_ENV_PATHS.find((candidate) => fs.existsSync(candidate));
  if (fallbackEnvPath) {
    const raw = fs.readFileSync(fallbackEnvPath, 'utf8');
    raw.split(/\r?\n/).forEach(line => {
      const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m) {
        const key = m[1];
        let val = m[2] || '';
        // strip surrounding quotes
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.substring(1, val.length-1);
        }
        if (!process.env[key]) process.env[key] = val;
      }
    });
    console.log('Loaded fallback env from', path.basename(fallbackEnvPath));
  }
} catch (e) {
  console.warn('Failed to load env fallback file', e && e.message);
}
const express = require("express");
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const app = express();
// When running behind a reverse proxy (nginx) enable trust proxy
app.set('trust proxy', 1);
const upload = multer({ storage: multer.memoryStorage() });
const s3UploadMiddleware = multer({
  storage: multer.memoryStorage(),
  limits: {
    // Hard limit at middleware level; detailed limits are enforced in the S3 service too.
    fileSize: Number(process.env.S3_MAX_FILE_SIZE_BYTES || 1024 * 1024 * 1024),
  },
});

const bufferToStream = (buffer) => {
  const stream = new Readable({
    read() {},
  });
  stream.push(buffer);
  stream.push(null);
  return stream;
};

const streamToString = async (body) => {
  if (!body) return '';
  if (typeof body.transformToString === 'function') {
    return body.transformToString('utf8');
  }
  if (Buffer.isBuffer(body)) {
    return body.toString('utf8');
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    body.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    body.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    body.on('error', reject);
  });
};

const timingSafeStringEqual = (left, right) => {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');
  if (leftBuffer.length !== rightBuffer.length) return false;
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
};

const verifyPbkdf2Password = (password, storedHash) => {
  const parts = String(storedHash || '').split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = Number(parts[1]);
  const salt = parts[2];
  const expected = parts[3];
  if (!Number.isFinite(iterations) || !salt || !expected) return false;
  const actual = crypto.pbkdf2Sync(String(password || ''), salt, iterations, 64, 'sha512').toString('hex');
  return timingSafeStringEqual(actual, expected);
};

let cachedAdminPasswordSecret = null;
let cachedAdminPasswordSecretAt = 0;
const ADMIN_SECRET_CACHE_MS = Number(process.env.ADMIN_SECRET_CACHE_MS || 5 * 60 * 1000);

const getAdminPasswordFromSecret = async () => {
  const secretId = String(process.env.ADMIN_PASSWORD_SECRET_ID || '').trim();
  if (!secretId) return null;
  const now = Date.now();
  if (cachedAdminPasswordSecret && now - cachedAdminPasswordSecretAt < ADMIN_SECRET_CACHE_MS) {
    return cachedAdminPasswordSecret;
  }

  const client = new SecretsManagerClient({ region: process.env.AWS_REGION || 'us-east-1' });
  const response = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
  const rawSecret = response.SecretString || (response.SecretBinary ? Buffer.from(response.SecretBinary).toString('utf8') : '');
  let secret = rawSecret;
  try {
    const parsed = JSON.parse(rawSecret);
    secret = parsed.ADMIN_PASSWORD || parsed.adminPassword || parsed.password || rawSecret;
  } catch (e) {}

  cachedAdminPasswordSecret = String(secret || '');
  cachedAdminPasswordSecretAt = now;
  return cachedAdminPasswordSecret;
};

const verifyAdminPassword = async (password) => {
  const passwordHash = String(process.env.ADMIN_PASSWORD_HASH || '').trim();
  if (passwordHash) {
    return verifyPbkdf2Password(password, passwordHash);
  }

  const secretPassword = await getAdminPasswordFromSecret();
  if (secretPassword) {
    return timingSafeStringEqual(password, secretPassword);
  }

  const envPassword = String(process.env.ADMIN_PASSWORD || '').trim();
  if (envPassword) {
    return timingSafeStringEqual(password, envPassword);
  }

  throw new Error('admin_password_not_configured');
};

const PORT = process.env.PORT || 8080;
// Allow binding the same app on multiple ports (e.g., 80, 443) via LISTEN_PORTS="8080,80,443"
const LISTEN_PORTS = (process.env.LISTEN_PORTS || String(PORT)).split(',').map(p => parseInt(p.trim(), 10)).filter(Number.isFinite);
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL || '604800', 10);
const deriveCookieDomain = () => {
  try {
    const domainSource = process.env.COOKIE_DOMAIN || process.env.HOSTNAME || '';
    if (!domainSource) return null;
    const cleaned = domainSource.replace(/^https?:\/\//, '').split(':')[0].trim().toLowerCase();
    if (!cleaned) return null;
    if (cleaned === 'localhost') return null;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(cleaned)) return null;
    const bare = cleaned.startsWith('www.') ? cleaned.substring(4) : cleaned;
    return bare.startsWith('.') ? bare : `.${bare}`;
  } catch (e) {
    return null;
  }
};
const SESSIONS_DIR = path.join(PRIVATE_DIR, '.sessions');
try {
  if (!fs.existsSync(SESSIONS_DIR)) {
    fs.mkdirSync(SESSIONS_DIR, { recursive: true });
    console.log('Created sessions directory:', SESSIONS_DIR);
  }
} catch (e) {
  console.warn('Failed to ensure sessions directory exists:', e && e.message);
}

const sessionStore = new FileStore({
  path: SESSIONS_DIR,
  // Don't perform multiple retries on transient file errors to avoid noisy logs
  retries: 0,
  ttl: SESSION_TTL_SECONDS,
  fileExtension: '.json'
});

// Log basic session configuration for debugging (no secrets)
try {
  console.log('Session store path:', SESSIONS_DIR);
  console.log('Session TTL (seconds):', SESSION_TTL_SECONDS);
  console.log('Derived cookie domain:', deriveCookieDomain());
} catch (e) {
  console.warn('Failed to log session configuration:', e && e.message);
}
const APP_FOLDER_NAME = "SimTk_Videos (Dont Delete)"; // Folder name for the app
// Compute redirect URI: prefer explicit env var, otherwise derive from HOSTNAME when possible
let REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || null;
if (!REDIRECT_URI) {
  const hostEnv = process.env.HOSTNAME || null;
  const hostOnly = hostEnv ? String(hostEnv).replace(/^https?:\/\//, '').trim() : null;
  if (hostOnly && !/localhost|127\.0\.0\.1/.test(hostOnly)) {
    REDIRECT_URI = `https://${hostOnly}/auth/google/callback`;
  } else {
    REDIRECT_URI = `http://localhost:${PORT}/auth/google/callback`;
  }
}
// Manual changes: update env vars in `.env` for local dev or your host config.

// Allow running without Google OAuth configured (Drive features will be disabled).
const DRIVE_CONFIGURED = Boolean(CLIENT_ID && CLIENT_SECRET);
if (!DRIVE_CONFIGURED) {
  console.warn("GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set — Google Drive features will be disabled.");
}

const TOKEN_PATH = path.join(PRIVATE_DIR, "token.json");

const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

console.log('Using OAuth REDIRECT_URI:', REDIRECT_URI);

if (fs.existsSync(TOKEN_PATH)) {
  const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH, "utf8"));
  oauth2Client.setCredentials(tokens);
}

const drive = google.drive({ version: "v3", auth: oauth2Client });

const DATA_DIR = path.join(PRIVATE_DIR, 'data');
const SCHOOLS_FILE = path.join(DATA_DIR, 'schools.json');

const ensureDataDir = () => {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
};

const readSchoolsFile = () => {
  try {
    ensureDataDir();
    if (!fs.existsSync(SCHOOLS_FILE)) return {};
    const raw = fs.readFileSync(SCHOOLS_FILE, 'utf8');
    return JSON.parse(raw || '{}');
  } catch (e) {
    console.warn('Failed to read schools file', e && e.message);
    return {};
  }
};

// Interests persistence (CTA submissions)
const INTERESTS_FILE = path.join(DATA_DIR, 'interests.json');

// Q&A submissions
const QUESTIONS_FILE = path.join(DATA_DIR, 'questions.json');

const readInterestsFile = () => {
  try {
    ensureDataDir();
    if (!fs.existsSync(INTERESTS_FILE)) return [];
    const raw = fs.readFileSync(INTERESTS_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (e) {
    console.warn('Failed to read interests file', e && e.message);
    return [];
  }
};

const writeInterestsFile = (arr) => {
  try {
    ensureDataDir();
    fs.writeFileSync(INTERESTS_FILE, JSON.stringify(arr, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to write interests file', e && e.message);
  }
};

const readQuestionsFile = () => {
  try {
    ensureDataDir();
    if (!fs.existsSync(QUESTIONS_FILE)) return [];
    const raw = fs.readFileSync(QUESTIONS_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (e) {
    console.warn('Failed to read questions file', e && e.message);
    return [];
  }
};

const writeQuestionsFile = (arr) => {
  try {
    ensureDataDir();
    fs.writeFileSync(QUESTIONS_FILE, JSON.stringify(arr, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to write questions file', e && e.message);
  }
};

// Mail notifications removed: server can run without `nodemailer` installed.
const writeSchoolsFile = (obj) => {
  try {
    ensureDataDir();
    fs.writeFileSync(SCHOOLS_FILE, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to write schools file', e && e.message);
  }
};

const updateSchoolRecord = (domain) => {
  if (!domain) return null;
  const schools = readSchoolsFile();
  if (!schools[domain]) schools[domain] = { count: 0, lastSeen: null };
  schools[domain].count = (schools[domain].count || 0) + 1;
  schools[domain].lastSeen = new Date().toISOString();
  writeSchoolsFile(schools);
  return schools[domain];
};

// Admin Management - CSV-based storage
const ADMINS_FILE = path.join(DATA_DIR, 'admins.csv');

const readAdminsCSV = () => {
  try {
    ensureDataDir();
    if (!fs.existsSync(ADMINS_FILE)) {
      // Create default admin file
      const header = 'name,email,approval,level,time\n';
      const defaultAdmin = 'Test Admin,testchant85@gmail.com,approved,super_admin,' + new Date().toISOString() + '\n';
      fs.writeFileSync(ADMINS_FILE, header + defaultAdmin, 'utf8');
    }
    const content = fs.readFileSync(ADMINS_FILE, 'utf8');
    const lines = content.trim().split('\n');
    if (lines.length <= 1) return []; // Only header
    
    const admins = [];
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(',');
      if (parts.length >= 5) {
        admins.push({
          name: parts[0],
          email: parts[1],
          approval: parts[2],
          level: parts[3],
          time: parts[4]
        });
      }
    }
    return admins;
  } catch (e) {
    console.warn('Failed to read admins CSV', e && e.message);
    return [];
  }
};

const writeAdminsCSV = (admins) => {
  try {
    ensureDataDir();
    let content = 'name,email,approval,level,time\n';
    admins.forEach(admin => {
      content += `${admin.name},${admin.email},${admin.approval},${admin.level},${admin.time}\n`;
    });
    fs.writeFileSync(ADMINS_FILE, content, 'utf8');
    return true;
  } catch (e) {
    console.error('Failed to write admins CSV', e && e.message);
    return false;
  }
};

const normalizeEmail = (email) => {
  return String(email || '').trim().toLowerCase();
};

const normalizeRole = (role) => {
  const value = String(role || '').trim().toLowerCase();
  if (value === 'teacher' || value === 'requested' || value === 'admin' || value === 'super_admin') {
    return value;
  }
  return 'student';
};

const isAdmin = (email) => {
  const target = normalizeEmail(email);
  if (!target) return false;
  const admins = readAdminsCSV();
  const admin = admins.find(a => normalizeEmail(a.email) === target && String(a.approval || '').trim().toLowerCase() === 'approved');
  return admin ? admin.level : null;
};

const isSuperAdmin = (email) => {
  const level = isAdmin(email);
  return level === 'super_admin';
};

// User Email Tracking - CSV-based local storage
const USERS_FILE = path.join(DATA_DIR, 'users.csv');

const readUsersCSV = () => {
  try {
    ensureDataDir();
    if (!fs.existsSync(USERS_FILE)) {
      fs.writeFileSync(USERS_FILE, 'name,email,first_login,last_login,login_count,requested\n', 'utf8');
    }
    let content = fs.readFileSync(USERS_FILE, 'utf8');
    const lines = content.trim().split('\n');
    // Migrate existing files that lack the `requested` column by rewriting with default false
    if (lines.length > 0) {
      const headerCols = (lines[0] || '').split(',').map(h => h.trim().toLowerCase());
      if (!headerCols.includes('requested')) {
        const newHeader = (lines[0] || '') + ',requested';
        const newRows = lines.slice(1).map(r => r + ',false');
        const newContent = [newHeader].concat(newRows).join('\n') + '\n';
        try {
          fs.writeFileSync(USERS_FILE, newContent, 'utf8');
          content = newContent;
        } catch (we) {
          console.warn('Failed to migrate users.csv to include requested column:', we && we.message);
        }
      }
    }
    const updatedLines = content.trim().split('\n');
    if (updatedLines.length <= 1) return []; // Only header

    const users = [];
    for (let i = 1; i < updatedLines.length; i++) {
      const parts = updatedLines[i].split(',');
      if (parts.length >= 5) {
        users.push({
          name: parts[0],
          email: parts[1],
          first_login: parts[2],
          last_login: parts[3],
          login_count: parseInt(parts[4], 10),
          requested: (parts[5] || '').toLowerCase() === 'true'
        });
      }
    }
    return users;
  } catch (e) {
    console.warn('Failed to read users CSV', e && e.message);
    return [];
  }
};

const writeUsersCSV = (users) => {
  try {
    ensureDataDir();
    let content = 'name,email,first_login,last_login,login_count,requested\n';
    users.forEach(user => {
      const req = user.requested ? 'true' : 'false';
      content += `${user.name},${user.email},${user.first_login},${user.last_login},${user.login_count},${req}\n`;
    });
    fs.writeFileSync(USERS_FILE, content, 'utf8');
    return true;
  } catch (e) {
    console.error('Failed to write users CSV', e && e.message);
    return false;
  }
};

// Read admins activity from CSV
const readAdminsActivity = () => {
  try {
    ensureDataDir();
    const adminsFile = path.join(DATA_DIR, 'admins_activity.csv');
    if (!fs.existsSync(adminsFile)) {
      fs.writeFileSync(adminsFile, 'name,email,first_login,last_login,login_count\n', 'utf8');
      return [];
    }
    const content = fs.readFileSync(adminsFile, 'utf8');
    const lines = content.trim().split('\n');
    if (lines.length <= 1) return [];
    
    const admins = [];
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(',');
      if (parts.length >= 5) {
        admins.push({
          name: parts[0],
          email: parts[1],
          first_login: parts[2],
          last_login: parts[3],
          login_count: parseInt(parts[4], 10)
        });
      }
    }
    return admins;
  } catch (e) {
    console.warn('Failed to read admins activity CSV', e && e.message);
    return [];
  }
};

// Read user permissions from CSV
const readUserPermissions = () => {
  try {
    ensureDataDir();
    const permFile = path.join(DATA_DIR, 'user_permissions.csv');
    if (!fs.existsSync(permFile)) {
      fs.writeFileSync(permFile, 'email,role,notes\n', 'utf8');
      return [];
    }
    const content = fs.readFileSync(permFile, 'utf8');
    const lines = content.trim().split('\n');
    if (lines.length <= 1) return [];
    
    const permissions = [];
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(',');
      if (parts.length >= 2) {
        const email = String(parts[0] || '').trim();
        if (!email) continue;
        permissions.push({
          email,
          role: normalizeRole(parts[1]),
          notes: (parts[2] || '').trim()
        });
      }
    }
    return permissions;
  } catch (e) {
    console.warn('Failed to read user permissions CSV', e && e.message);
    return [];
  }
};

// Get role for a given user email from permissions
const getUserRole = (email) => {
  try {
    const target = normalizeEmail(email);
    if (!target) return 'student';
    const perms = readUserPermissions();
    const found = perms.find(p => normalizeEmail(p.email) === target);
    return found ? normalizeRole(found.role) : 'student';
  } catch (e) {
    return 'student';
  }
};

const refreshSessionAuthFlags = (req) => {
  try {
    if (!req || !req.session) return;

    const sessionUser = req.session.user;
    const storedAdmin = req.session.adminUser;
    const normalizedStoredAdmin = storedAdmin && normalizeEmail(storedAdmin.email);
    const normalizedEmail = sessionUser && sessionUser.email ? normalizeEmail(sessionUser.email) : null;

    if (normalizedEmail) {
      let adminLevel = isAdmin(normalizedEmail);
      if (adminLevel) {
        if (!storedAdmin || normalizedStoredAdmin !== normalizedEmail) {
          req.session.adminUser = {
            email: sessionUser.email,
            name: sessionUser.name || sessionUser.email,
            level: adminLevel,
            loginTime: new Date().toISOString(),
          };
        } else {
          req.session.adminUser.level = adminLevel;
        }
      } else if (storedAdmin && normalizedStoredAdmin === normalizedEmail) {
        delete req.session.adminUser;
      }

      const derivedRole = adminLevel ? 'admin' : getUserRole(normalizedEmail);
      req.session.userRole = derivedRole || 'student';
      req.session.isTeacher = Boolean(adminLevel || derivedRole === 'teacher');
    } else if (!sessionUser && storedAdmin) {
      // Admin session restored but user object missing (e.g., password login only)
      req.session.user = {
        email: storedAdmin.email,
        name: storedAdmin.name || storedAdmin.email,
      };
      req.session.userRole = 'admin';
      req.session.isTeacher = true;
    }
  } catch (e) {
    console.warn('refreshSessionAuthFlags error', e && e.message);
  }
};

const hasTeacherPrivileges = (req) => {
  try {
    refreshSessionAuthFlags(req);
    if (!req || !req.session) return false;
    if (req.session.adminUser) return true;
    const sessionRole = normalizeRole(req.session.userRole);
    if (sessionRole === 'teacher') return true;
    if (req.session.isTeacher) return true;
    const email = req.session.user && req.session.user.email;
    if (email && getUserRole(email) === 'teacher') return true;
    return false;
  } catch (e) {
    console.warn('hasTeacherPrivileges error', e && e.message);
    return false;
  }
};

// Sync `requested` flags in users.csv from permissions and interests.
const syncRequestedFlags = () => {
  try {
    ensureDataDir();
    const users = readUsersCSV();
    const permissions = readUserPermissions();
    const interests = readInterestsFile();

    const requestedSet = new Set();
    // permissions with role 'requested'
    (permissions || []).forEach(p => {
      if (!p || !p.email) return;
      if (normalizeRole(p.role) === 'requested') {
        requestedSet.add(normalizeEmail(p.email));
      }
    });
    // interests pending teacher requests
    (interests || []).forEach(i => {
      if (!i || !i.email) return;
      const role = normalizeRole(i.role);
      const status = String(i.status || '').trim().toLowerCase();
      if (role === 'teacher' && status !== 'approved' && status !== 'denied') {
        requestedSet.add(normalizeEmail(i.email));
      }
    });

    // users.csv explicit requested flags (acts as an additional source of truth
    // so requests created by older flows are not lost until admin acts)
    (users || []).forEach(u => {
      if (!u || !u.email) return;
      if (u.requested) {
        requestedSet.add(normalizeEmail(u.email));
      }
    });

    let changed = false;
    users.forEach(u => {
      const lower = normalizeEmail(u.email);
      const should = requestedSet.has(lower);
      if (Boolean(u.requested) !== Boolean(should)) {
        u.requested = should;
        changed = true;
      }
    });
    if (changed) writeUsersCSV(users);
    return true;
  } catch (e) {
    console.warn('syncRequestedFlags error', e && e.message);
    return false;
  }
};

const trackUserLogin = (name, email) => {
  try {
    if (!email) return false;
    
    // Check if user is admin first
    const adminLevel = isAdmin(email);
    
    if (adminLevel) {
      // Track admin in separate file
      const adminsFile = path.join(DATA_DIR, 'admins_activity.csv');
      let admins = [];
      
      if (fs.existsSync(adminsFile)) {
        const content = fs.readFileSync(adminsFile, 'utf8');
        const lines = content.trim().split('\n');
        admins = lines.slice(1).map(line => {
          const [n, e, first, last, count] = line.split(',');
          return { name: n, email: e, first_login: first, last_login: last, login_count: parseInt(count) || 0 };
        });
      }
      
      const now = new Date().toISOString();
      const existingIndex = admins.findIndex(a => a.email.toLowerCase() === email.toLowerCase());
      
      if (existingIndex !== -1) {
        admins[existingIndex].last_login = now;
        admins[existingIndex].login_count = (admins[existingIndex].login_count || 0) + 1;
        console.log(`Admin login tracked (update): ${email} (login #${admins[existingIndex].login_count})`);
      } else {
        admins.push({
          name: name || email,
          email: email,
          first_login: now,
          last_login: now,
          login_count: 1
        });
        console.log(`Admin login tracked (new): ${email}`);
      }
      
      // Write back to admins_activity.csv
      const header = 'name,email,first_login,last_login,login_count\n';
      const rows = admins.map(a => `${a.name},${a.email},${a.first_login},${a.last_login},${a.login_count}`).join('\n');
      fs.writeFileSync(adminsFile, header + rows, 'utf8');
      return true;
    }
    
    // Track regular user in users.csv
    const users = readUsersCSV();
    const now = new Date().toISOString();
    
    // Check if user already exists
    const existingIndex = users.findIndex(u => u.email.toLowerCase() === email.toLowerCase());
    
    if (existingIndex !== -1) {
      // Update existing user
      users[existingIndex].last_login = now;
      users[existingIndex].login_count = (users[existingIndex].login_count || 0) + 1;
      if (name && !users[existingIndex].name) {
        users[existingIndex].name = name;
      }
      console.log(`User login tracked (update): ${email} (login #${users[existingIndex].login_count})`);
    } else {
      // Add new user
      users.push({
        name: name || email,
        email: email,
        first_login: now,
        last_login: now,
        login_count: 1
      });
      // Ensure requested flag defaults to false for new users
      if (users[users.length - 1]) users[users.length - 1].requested = false;
      console.log(`User login tracked (new): ${email}`);
    }
    
    return writeUsersCSV(users);
  } catch (e) {
    console.error('Failed to track user login:', e && e.message);
    return false;
  }
};

// Q&A Text File management on Google Drive (stored inside app folder)
const Q_AND_A_FILE_NAME = "SimTk_QnA.txt";

const getOrCreateQnAFile = async (drive, parentFolderId) => {
  try {
    if (!parentFolderId) {
      console.error('getOrCreateQnAFile: No parent folder ID provided');
      return null;
    }
    
    // Search for existing Q&A text file inside the app folder
    const response = await drive.files.list({
      q: `name='${Q_AND_A_FILE_NAME}' and mimeType='text/plain' and trashed=false and '${parentFolderId}' in parents`,
      fields: "files(id, name)",
      spaces: "drive",
    });

    if (response.data.files && response.data.files.length > 0) {
      console.log(`Found existing Q&A file: ${response.data.files[0].id}`);
      return response.data.files[0].id;
    }

    // Create new file if not found
    console.log(`Creating new Q&A text file in folder: ${parentFolderId}`);
    const fileMetadata = {
      name: Q_AND_A_FILE_NAME,
      mimeType: "text/plain",
      parents: [parentFolderId],
    };
    const file = await drive.files.create({
      requestBody: fileMetadata,
      media: {
        mimeType: "text/plain",
        body: "SimTk Q&A Questions Log\n" + "=".repeat(50) + "\n\n",
      },
      fields: "id",
    });
    console.log(`Created Q&A file with ID: ${file.data.id}`);
    return file.data.id;
  } catch (error) {
    console.error("Error getting/creating Q&A file:", error && error.message);
    return null;
  }
};

const appendToQnAFile = async (drive, fileId, entry) => {
  try {
    // Read current content
    const res = await drive.files.get(
      { fileId, alt: "media" },
      { responseType: "stream" }
    );
    let content = '';
    await new Promise((resolve, reject) => {
      res.data.on('data', chunk => (content += chunk));
      res.data.on('end', resolve);
      res.data.on('error', reject);
    });

    // Append new entry
    const timestamp = new Date().toISOString();
    const newEntry = `[${timestamp}] ${entry.name || 'Anonymous'} (${entry.email || 'no-email'})\nQ: ${entry.question}\n\n`;
    const updatedContent = content + newEntry;

    // Update file
    await drive.files.update({
      fileId,
      media: {
        mimeType: "text/plain",
        body: updatedContent,
      },
    });
    return true;
  } catch (error) {
    console.error("Error appending to Q&A file:", error);
    return false;
  }
};

const readQnAFile = async (drive, fileId) => {
  try {
    const res = await drive.files.get(
      { fileId, alt: "media" },
      { responseType: "stream" }
    );
    let content = '';
    await new Promise((resolve, reject) => {
      res.data.on('data', chunk => (content += chunk));
      res.data.on('end', resolve);
      res.data.on('error', reject);
    });
    
    // Parse the text file into questions with line tracking
    const lines = content.split('\n');
    const questions = [];
    let currentQ = null;
    let questionStartLine = -1;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith('[') && line.includes(']')) {
        if (currentQ) {
          currentQ.endLine = i - 1;
          questions.push(currentQ);
        }
        questionStartLine = i;
        const match = line.match(/\[([^\]]+)\]\s+(.+?)\s+\((.+?)\)/);
        if (match) {
          const timestamp = match[1];
          currentQ = {
            id: Buffer.from(timestamp).toString('hex').substr(0, 16), // Consistent ID from timestamp
            createdAt: timestamp,
            name: match[2],
            email: match[3],
            question: '',
            startLine: i
          };
        }
      } else if (line.startsWith('Q: ') && currentQ) {
        currentQ.question = line.substring(3);
      }
    }
    if (currentQ) {
      currentQ.endLine = lines.length - 1;
      questions.push(currentQ);
    }
    
    return questions.reverse(); // newest first
  } catch (error) {
    console.error("Error reading Q&A file:", error);
    return [];
  }
};

// Configure AWS S3 client (uses env vars AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION)
let s3 = null;
try {
  if (process.env.S3_BUCKET_NAME && process.env.AWS_REGION) {
    s3 = createS3Client();
  } else {
    console.log('S3 not configured: S3_BUCKET_NAME or AWS_REGION missing');
  }
} catch (e) {
  console.warn('Failed to initialize S3 client:', e && e.message);
  s3 = null;
}

// Helper: sanitize folder name for S3 keys
const sanitizeFolderName = (name) => {
  if (!name) return 'unknown_user';
  return String(name).replace(/[\\\\\/:*?"<>|\r\n]+/g, '_').trim();
};

// Compose user folder prefix: "email FirstName LastName/"
const makeUserFolderPrefix = (email, fullName) => {
  const namePart = fullName || '';
  const folder = `${email || 'unknown'} ${namePart}`.trim();
  return sanitizeFolderName(folder) + '/';
};

// Ensure a minimal profile file exists for the user in S3; returns true if exists or created
const ensureUserProfileInS3 = async (email, fullName) => {
  try {
    if (!email) return false;
    const prefix = makeUserFolderPrefix(email, fullName);
    const Bucket = process.env.S3_BUCKET_NAME;
    if (!Bucket) return false;

    // Extra safety: do not create profiles for admin emails (check admins.csv)
    try {
      const admins = readAdminsCSV();
      const isAdminUser = admins.some(a => normalizeEmail(a.email) === normalizeEmail(email));
      if (isAdminUser) {
        console.log('Skipping S3 profile creation for admin email:', email);
        return false;
      }
    } catch (e) {
      console.warn('Failed to read admins CSV while checking S3 profile creation:', e && e.message);
      // continue cautiously
    }

    // Look for profile.json
    const list = await s3.send(new ListObjectsV2Command({ Bucket, Prefix: prefix, MaxKeys: 50 }));
    const hasProfile = (list.Contents || []).some(o => o.Key === (prefix + 'profile.json'));
    if (hasProfile) return true;

    // Create a default profile JSON and a human-readable TXT placeholder
    const profile = {
      name: fullName || '',
      interests: [],
      years_experience: null,
      want_to_teach: false,
      createdAt: new Date().toISOString()
    };

    // Upload JSON
    await s3.send(new PutObjectCommand({
      Bucket,
      Key: prefix + 'profile.json',
      Body: JSON.stringify(profile, null, 2),
      ContentType: 'application/json'
    }));

    // Upload TXT
    const txt = `Name: ${profile.name}\nField of interest (up to 3): ${profile.interests.join(', ')}\nYears of experience: ${profile.years_experience || ''}\nWants to become a teacher: ${profile.want_to_teach ? 'Yes' : 'No'}\n`;
    await s3.send(new PutObjectCommand({
      Bucket,
      Key: prefix + 'profile.txt',
      Body: txt,
      ContentType: 'text/plain'
    }));

    return true;
  } catch (err) {
    console.warn('ensureUserProfileInS3 error', err && err.message);
    return false;
  }
};
// Manual change: set DRIVE_FOLDER_ID in `.env` to upload into a shared folder.

// Route53 helper: optionally ensure an A record for HOSTNAME points to this host's public IP
const HOSTED_ZONE_ID = process.env.HOSTED_ZONE_ID || null;
const AUTO_ROUTE53 = String(process.env.AUTO_ROUTE53 || 'false').toLowerCase() === 'true';
const ROUTE53_TTL = parseInt(process.env.ROUTE53_TTL || '300', 10);

// Alibaba Cloud DNS (ALIDNS) automation
const AUTO_ALIDNS = String(process.env.AUTO_ALIDNS || 'false').toLowerCase() === 'true';
const ALIYUN_ACCESS_KEY_ID = process.env.ALIYUN_ACCESS_KEY_ID || null;
const ALIYUN_ACCESS_KEY_SECRET = process.env.ALIYUN_ACCESS_KEY_SECRET || null;
const ALIDNS_TTL = parseInt(process.env.ALIDNS_TTL || String(ROUTE53_TTL || '300'), 10);
const ALIDNS_DOMAIN = (process.env.ALIDNS_DOMAIN || process.env.HOSTNAME || '').replace(/^https?:\/\//, '').trim() || null;


const getPublicIp = () => {
  return new Promise((resolve, reject) => {
    try {
      https.get('https://checkip.amazonaws.com/', (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => resolve((data || '').trim()));
      }).on('error', reject);
    } catch (e) {
      reject(e);
    }
  });
};

const ensureRoute53ARecord = async () => {
  if (!AUTO_ROUTE53) return { ok: false, reason: 'AUTO_ROUTE53 disabled' };
  if (!HOSTED_ZONE_ID) return { ok: false, reason: 'HOSTED_ZONE_ID missing' };
  const domain = (process.env.HOSTNAME || '').replace(/^https?:\/\//, '').trim();
  if (!domain) return { ok: false, reason: 'HOSTNAME missing' };

  const r53 = new Route53Client({ region: process.env.AWS_REGION || 'us-east-1' });
  try {
    const ip = await getPublicIp();
    if (!ip) return { ok: false, reason: 'failed to fetch public ip' };

    // Fetch current record
    const list = await r53.send(new ListResourceRecordSetsCommand({
      HostedZoneId: HOSTED_ZONE_ID,
      StartRecordName: domain,
      MaxItems: '1',
    }));

    const existing = (list.ResourceRecordSets || []).find(r => r.Name.replace(/\.$/, '') === domain && r.Type === 'A');
    const needsUpdate = !existing || !existing.ResourceRecords || existing.ResourceRecords[0].Value !== ip;

    if (!needsUpdate) return { ok: true, reason: 'record up-to-date', ip };

    const change = {
      HostedZoneId: HOSTED_ZONE_ID,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: domain,
              Type: 'A',
              TTL: ROUTE53_TTL,
              ResourceRecords: [{ Value: ip }],
            }
          }
        ]
      }
    };

    const resp = await r53.send(new ChangeResourceRecordSetsCommand(change));
    return { ok: true, ip, changeId: resp.ChangeInfo && resp.ChangeInfo.Id };
  } catch (err) {
    console.error('Route53 sync error', err && err.message);
    return { ok: false, reason: err && err.message };
  }
};

const ensureAlidnsARecord = async () => {
  if (!AUTO_ALIDNS) return { ok: false, reason: 'AUTO_ALIDNS disabled' };
  if (!ALIYUN_ACCESS_KEY_ID || !ALIYUN_ACCESS_KEY_SECRET) return { ok: false, reason: 'ALIYUN credentials missing' };
  const domain = ALIDNS_DOMAIN;
  if (!domain) return { ok: false, reason: 'ALIDNS_DOMAIN/HOSTNAME missing' };

  try {
    const ip = await getPublicIp();
    if (!ip) return { ok: false, reason: 'failed to fetch public ip' };

    // Call Alibaba Alidns API via HTTP
    const listParams = new URLSearchParams({
      Action: 'DescribeDomainRecords',
      DomainName: domain,
      PageNumber: '1',
      PageSize: '10',
      Version: '2015-01-09',
    });

    const listResp = await callAlidnsApi(listParams);
    const records = (listResp && listResp.DomainRecords && listResp.DomainRecords.Record) || [];

    // Find existing A record at root
    const existing = records.find(r => r.Type === 'A' && r.RR === '@');
    
    if (existing && existing.Value === ip) {
      return { ok: true, reason: 'record up-to-date', ip };
    }

    if (existing) {
      // Update existing record
      const updateParams = new URLSearchParams({
        Action: 'UpdateDomainRecord',
        RecordId: existing.RecordId,
        RR: '@',
        Type: 'A',
        Value: ip,
        TTL: String(ALIDNS_TTL),
        Version: '2015-01-09',
      });
      await callAlidnsApi(updateParams);
      return { ok: true, ip, action: 'updated', recordId: existing.RecordId };
    }

    // Create new record
    const addParams = new URLSearchParams({
      Action: 'AddDomainRecord',
      DomainName: domain,
      RR: '@',
      Type: 'A',
      Value: ip,
      TTL: String(ALIDNS_TTL),
      Version: '2015-01-09',
    });
    const addResp = await callAlidnsApi(addParams);
    return { ok: true, ip, action: 'created', recordId: addResp && addResp.RecordId };
  } catch (err) {
    console.error('Alidns sync error', err && err.message);
    return { ok: false, reason: err && err.message };
  }
};

const callAlidnsApi = async (params) => {
  const queryString = params.toString();
  const stringToSign = `GET&${encodeURIComponent('/')}&${encodeURIComponent(queryString)}`;
  const hmac = crypto.createHmac('sha1', `${ALIYUN_ACCESS_KEY_SECRET}&`);
  hmac.update(stringToSign);
  const signature = hmac.digest('base64');
  const url = `https://alidns.aliyuncs.com/?${queryString}&Signature=${encodeURIComponent(signature)}&AccessKeyId=${ALIYUN_ACCESS_KEY_ID}&SignatureMethod=HMAC-SHA1&SignatureVersion=1.0&Timestamp=${new Date().toISOString()}&SignatureNonce=${Math.random()}`;

  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          // Try JSON first, then XML
          if (data.includes('<?xml') || data.includes('<')) {
            const parsed = parseXmlToJson(data);
            resolve(parsed);
          } else {
            const parsed = JSON.parse(data);
            resolve(parsed);
          }
        } catch (e) {
          reject(new Error(`Failed to parse Alidns response: ${e.message}`));
        }
      });
    }).on('error', reject);
  });
};

const parseXmlToJson = (xml) => {
  const result = {};
  
  // Extract RecordId
  const recordIdMatch = xml.match(/<RecordId>([^<]+)<\/RecordId>/);
  if (recordIdMatch) result.RecordId = recordIdMatch[1];
  
  // Extract DomainRecords
  const recordsMatch = xml.match(/<DomainRecord>([\s\S]*?)<\/DomainRecord>/g);
  if (recordsMatch) {
    result.DomainRecords = { Record: [] };
    recordsMatch.forEach(recordXml => {
      const record = {};
      const typeMatch = recordXml.match(/<Type>([^<]+)<\/Type>/);
      const rrMatch = recordXml.match(/<RR>([^<]+)<\/RR>/);
      const valueMatch = recordXml.match(/<Value>([^<]+)<\/Value>/);
      const recordIdMatch = recordXml.match(/<RecordId>([^<]+)<\/RecordId>/);
      
      if (typeMatch) record.Type = typeMatch[1];
      if (rrMatch) record.RR = rrMatch[1];
      if (valueMatch) record.Value = valueMatch[1];
      if (recordIdMatch) record.RecordId = recordIdMatch[1];
      
      result.DomainRecords.Record.push(record);
    });
  }
  
  return result;
};

app.use(express.json());

// Detect if request is from local network and store local IP info
app.use((req, res, next) => {
  const clientIp = req.ip || req.connection.remoteAddress || '';
  const isLocal = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|localhost)/.test(clientIp);
  req.isLocalNetwork = isLocal;
  req.clientIp = clientIp;
  next();
});

app.use(
  session({
    name: process.env.SESSION_COOKIE_NAME || 'simtk.sid',
    store: sessionStore,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: (function(){
      const cookie = { sameSite: 'lax', maxAge: SESSION_TTL_SECONDS * 1000, secure: false };
      const domainOverride = deriveCookieDomain();
      if (domainOverride) {
        cookie.domain = domainOverride;
      }
      // Explicitly set secure cookie when FORCE_SECURE=true
      cookie.secure = process.env.FORCE_SECURE === 'true';
      return cookie;
    })(),
  })
);

// Prevent accidental exposure of sensitive files via static serving.
// Block token file, .env, session directory, and data directory paths explicitly.
app.use((req, res, next) => {
  try {
    const p = String(req.path || '').toLowerCase();
    const blocked = ['/token.json', '/.env', '/.sessions', '/.sessions/', '/server.js', '/package.json', '/data', '/data/'];
    for (const b of blocked) {
      if (p === b || p.startsWith(b)) {
        return res.status(404).end();
      }
    }
  } catch (e) {}
  return next();
});

// Serve site files (safe defaults)
app.use(express.static(PUBLIC_DIR, { dotfiles: 'ignore', index: false }));

// Serve index at root explicitly so browsers visiting `/` get the homepage.
app.get('/', (req, res) => {
  try {
    return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  } catch (e) {
    return res.status(500).send('server_error');
  }
});

if (process.env.HOSTNAME) console.log('Configured HOSTNAME:', process.env.HOSTNAME);

// Provide network info endpoint for clients to determine local vs external
app.get("/network-info", (req, res) => {
  const localIP = process.env.LOCAL_IP || '10.0.0.2';
  const publicIP = '24.127.20.36';
  res.json({
    isClientLocal: req.isLocalNetwork,
    clientIp: req.clientIp,
    recommendedAccess: req.isLocalNetwork ? localIP : publicIP,
    localIP: localIP,
    publicIP: publicIP,
    domain: process.env.HOSTNAME || 'simtkus.com'
  });
});

const buildAuthedClient = (tokens) => {
  const client = new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI
  );
  client.setCredentials(tokens);
  return client;
};

const getDriveForRequest = (req) => {
  if (!DRIVE_CONFIGURED) return null;
  const tokens = req.session.tokens || oauth2Client.credentials;
  if (!tokens || (!tokens.access_token && !tokens.refresh_token)) {
    return null;
  }
  const client = buildAuthedClient(tokens);
  return google.drive({ version: "v3", auth: client });
};

const isInsufficientScopeError = (err) => {
  try {
    if (!err) return false;
    if (err.code === 403) return true;
    if (err.response && err.response.status === 403) return true;
    const msgs = (err.errors || []).map(e => e.reason || e.message || '').join(' ');
    if (/insufficientPermission|insufficient_scope|Insufficient Permission/i.test(msgs)) return true;
    if (err.response && err.response.data && err.response.data.error && err.response.data.error.errors) {
      return err.response.data.error.errors.some(e => /insufficientPermission|insufficient_scope/i.test(e.reason || e.message || ''));
    }
    return false;
  } catch (e) { return false; }
};

const clearStoredTokens = (req) => {
  try {
    oauth2Client.setCredentials({});
  } catch (e) {}
  try {
    if (fs.existsSync(TOKEN_PATH)) fs.unlinkSync(TOKEN_PATH);
  } catch (e) {}
  try {
    if (req && req.session) {
      delete req.session.tokens;
      delete req.session.appFolderId;
      delete req.session.user;
      delete req.session.school;
      delete req.session.schoolDomain;
      req.session.save && req.session.save(()=>{});
    }
  } catch (e) {}
};

// ===== GOOGLE DRIVE STORAGE FUNCTIONS =====
// Backup system: Store CSV files in Drive folder (separate CSV files)

// Get or create the SimTk backup folder in Google Drive
const getOrCreateSimTkBackupFolder = async (drive) => {
  try {
    const folderName = 'SimTk_Backup';
    
    // Search for existing folder
    const res = await drive.files.list({
      q: `name='${folderName}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
      spaces: 'drive',
      fields: 'files(id, name)',
      pageSize: 1
    });
    
    if (res.data.files && res.data.files.length > 0) {
      console.log('Found existing SimTk_Backup folder on Drive');
      return res.data.files[0].id;
    }
    
    // Create new folder if doesn't exist
    const createRes = await drive.files.create({
      resource: { 
        name: folderName, 
        mimeType: 'application/vnd.google-apps.folder',
        description: 'SimTk Backup - CSV files backup'
      },
      fields: 'id'
    });
    
    console.log('Created new SimTk_Backup folder on Drive');
    return createRes.data.id;
  } catch (err) {
    console.error('Error getting/creating backup folder:', err.message);
    return null;
  }
};

// Get or create a CSV file in the backup folder
const getOrCreateBackupFile = async (drive, folderId, fileName) => {
  try {
    if (!folderId) return null;
    
    // Search for file in folder
    const res = await drive.files.list({
      q: `name='${fileName}' and mimeType='text/plain' and trashed=false and '${folderId}' in parents`,
      spaces: 'drive',
      fields: 'files(id, name)',
      pageSize: 1
    });
    
    if (res.data.files && res.data.files.length > 0) {
      return res.data.files[0].id;
    }
    
    // Create new file
    const createRes = await drive.files.create({
      resource: { 
        name: fileName, 
        mimeType: 'text/plain',
        parents: [folderId]
      },
      media: { 
        mimeType: 'text/plain', 
        body: ''
      },
      fields: 'id'
    });
    
    console.log(`Created backup file: ${fileName}`);
    return createRes.data.id;
  } catch (err) {
    console.error('Error creating backup file:', err.message);
    return null;
  }
};

// Read CSV file from Drive
const readBackupFile = async (drive, fileId) => {
  try {
    if (!fileId) return '';
    const res = await drive.files.get({
      fileId: fileId,
      alt: 'media'
    });
    return res.data || '';
  } catch (err) {
    console.warn('Error reading backup file:', err.message);
    return '';
  }
};

// Write CSV file to Drive
const writeBackupFile = async (drive, fileId, content) => {
  try {
    if (!fileId) return false;
    await drive.files.update({
      fileId: fileId,
      media: { 
        mimeType: 'text/plain', 
        body: content
      }
    });
    return true;
  } catch (err) {
    console.warn('Error writing backup file:', err.message);
    return false;
  }
};

// Backup all local CSV files to Drive
const backupAllFilesToDrive = async (drive) => {
  try {
    const folderId = await getOrCreateSimTkBackupFolder(drive);
    if (!folderId) {
      console.warn('Could not get/create backup folder');
      return false;
    }
    
    // Backup users.csv
    if (fs.existsSync(USERS_FILE)) {
      const content = fs.readFileSync(USERS_FILE, 'utf8');
      const fileId = await getOrCreateBackupFile(drive, folderId, 'users.csv');
      await writeBackupFile(drive, fileId, content);
      console.log('✓ Backed up users.csv to Drive');
    }
    
    // Backup admins_activity.csv
    const adminsFile = path.join(DATA_DIR, 'admins_activity.csv');
    if (fs.existsSync(adminsFile)) {
      const content = fs.readFileSync(adminsFile, 'utf8');
      const fileId = await getOrCreateBackupFile(drive, folderId, 'admins_activity.csv');
      await writeBackupFile(drive, fileId, content);
      console.log('✓ Backed up admins_activity.csv to Drive');
    }
    
    // Backup user_permissions.csv
    const permFile = path.join(DATA_DIR, 'user_permissions.csv');
    if (fs.existsSync(permFile)) {
      const content = fs.readFileSync(permFile, 'utf8');
      const fileId = await getOrCreateBackupFile(drive, folderId, 'user_permissions.csv');
      await writeBackupFile(drive, fileId, content);
      console.log('✓ Backed up user_permissions.csv to Drive');
    }
    
    // Backup schools.json
    if (fs.existsSync(SCHOOLS_FILE)) {
      const content = fs.readFileSync(SCHOOLS_FILE, 'utf8');
      const fileId = await getOrCreateBackupFile(drive, folderId, 'schools.json');
      await writeBackupFile(drive, fileId, content);
      console.log('✓ Backed up schools.json to Drive');
    }
    
    // Backup questions.json
    if (fs.existsSync(QUESTIONS_FILE)) {
      const content = fs.readFileSync(QUESTIONS_FILE, 'utf8');
      const fileId = await getOrCreateBackupFile(drive, folderId, 'questions.json');
      await writeBackupFile(drive, fileId, content);
      console.log('✓ Backed up questions.json to Drive');
    }
    
    return true;
  } catch (err) {
    console.error('Backup error:', err.message);
    return false;
  }
};

// Read complete data from simtk_management file
const readSimTkDataFromDrive = async (drive) => {
  try {
    const fileId = await getOrCreateSimTkManagementFile(drive);
    if (!fileId) {
      console.warn('Could not access simtk_management file');
      return null;
    }
    
    const res = await drive.files.get({
      fileId: fileId,
      alt: 'media'
    });
    
    const data = typeof res.data === 'string' ? JSON.parse(res.data) : res.data;
    console.log('Loaded data from Drive: users=' + data.users?.length + ', admins=' + data.admins?.length);
    return data;
  } catch (err) {
    console.error('Error reading simtk_management from Drive:', err.message);
    return null;
  }
};

// Write complete data to simtk_management file
const writeSimTkDataToDrive = async (drive, data) => {
  try {
    const fileId = await getOrCreateSimTkManagementFile(drive);
    if (!fileId) {
      console.warn('Could not access simtk_management file for writing');
      return false;
    }
    
    const dataWithTimestamp = {
      ...data,
      lastUpdated: new Date().toISOString()
    };
    
    await drive.files.update({
      fileId: fileId,
      media: { 
        mimeType: 'application/octet-stream', 
        body: JSON.stringify(dataWithTimestamp, null, 2)
      }
    });
    
    console.log('Updated simtk_management on Drive');
    return true;
  } catch (err) {
    console.error('Error writing simtk_management to Drive:', err.message);
    return false;
  }
};

// Sync all local data with Drive (Drive is primary)
const syncAllDataWithDrive = async (drive) => {
  try {
    console.log('Starting sync with Drive...');
    
    // Try to read from Drive (primary source)
    const driveData = await readSimTkDataFromDrive(drive);
    
    if (driveData && driveData.users && driveData.users.length > 0) {
      // Drive has data - update local files from Drive
      console.log('Syncing from Drive to local files...');
      
      // Update users.csv
      const usersCsv = 'name,email,first_login,last_login,login_count\n' + 
        driveData.users.map(u => `${u.name},${u.email},${u.first_login},${u.last_login},${u.login_count}`).join('\n');
      fs.writeFileSync(USERS_FILE, usersCsv, 'utf8');
      
      // Update admins_activity.csv
      const adminsCsv = 'name,email,first_login,last_login,login_count\n' + 
        driveData.admins.map(a => `${a.name},${a.email},${a.first_login},${a.last_login},${a.login_count}`).join('\n');
      fs.writeFileSync(path.join(DATA_DIR, 'admins_activity.csv'), adminsCsv, 'utf8');
      
      // Update user_permissions.csv
      const permCsv = 'email,role,notes\n' + 
        driveData.permissions.map(p => `${p.email},${p.role},${p.notes || ''}`).join('\n');
      fs.writeFileSync(path.join(DATA_DIR, 'user_permissions.csv'), permCsv, 'utf8');
      
      // Update schools.json
      fs.writeFileSync(path.join(DATA_DIR, 'schools.json'), JSON.stringify(driveData.schools, null, 2), 'utf8');
      
      // Update questions.json
      fs.writeFileSync(path.join(DATA_DIR, 'questions.json'), JSON.stringify(driveData.questions || [], null, 2), 'utf8');
      
      return true;
    } else {
      // Drive is empty - upload all local data to Drive
      console.log('Syncing from local to Drive...');
      
      const dataToUpload = {
        users: readUsersCSV(),
        admins: readAdminsActivity(),
        permissions: readUserPermissions(),
        schools: readSchoolsFile(),
        questions: readQuestionsFile(),
        lastUpdated: new Date().toISOString()
      };
      
      return await writeSimTkDataToDrive(drive, dataToUpload);
    }
  } catch (err) {
    console.error('Sync error:', err.message);
    return false;
  }
};

// Find or create the app folder in Google Drive
const getOrCreateAppFolder = async (drive) => {
  try {
    // Search for existing folder
    const response = await drive.files.list({
      q: `name='${APP_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
      fields: "files(id, name)",
      spaces: "drive",
    });

    if (response.data.files && response.data.files.length > 0) {
      console.log(`Found existing folder: ${APP_FOLDER_NAME} (${response.data.files[0].id})`);
      return response.data.files[0].id;
    }

    // Create new folder if not found
    console.log(`Creating new folder: ${APP_FOLDER_NAME}`);
    const folderMetadata = {
      name: APP_FOLDER_NAME,
      mimeType: "application/vnd.google-apps.folder",
    };
    const folder = await drive.files.create({
      requestBody: folderMetadata,
      fields: "id",
    });
    console.log(`Created folder with ID: ${folder.data.id}`);
    return folder.data.id;
  } catch (error) {
    console.error("Error getting/creating folder:", error);
    return null;
  }
};

// Guard route handlers that require valid Drive credentials.
const ensureAuthed = (req, res, next) => {
  if (!DRIVE_CONFIGURED) {
    return res.status(503).json({ error: 'drive_unconfigured', message: 'Server not configured with Google OAuth' });
  }
  const creds = req.session.tokens || oauth2Client.credentials;
  if (creds && (creds.access_token || creds.refresh_token)) {
    return next();
  }
  return res.status(401).json({ error: "not_authenticated" });
};

// Start OAuth flow by redirecting to Google's consent screen.
app.get("/auth/google", (req, res) => {
  // Request Drive access plus OpenID/email so we can identify the user
  const scopes = [
    "https://www.googleapis.com/auth/drive.file",
    "openid",
    "email",
    "profile",
  ];
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: scopes,
    prompt: "consent",
  });
  res.redirect(url);
});

// Handle OAuth callback and persist tokens for future sessions.
app.get("/auth/google/callback", async (req, res) => {
  try {
    const { code } = req.query;
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
    req.session.tokens = tokens;
    
    // Create app folder on first login
    const drive = google.drive({ version: "v3", auth: oauth2Client });
    const folderId = await getOrCreateAppFolder(drive);
    if (folderId) {
      req.session.appFolderId = folderId;
    }

    // Fetch basic userinfo (email) and derive a school name
    try {
      const oauth2 = google.oauth2({ auth: oauth2Client, version: "v2" });
      const userinfoRes = await oauth2.userinfo.get();
      const user = userinfoRes.data || {};
      req.session.user = { email: user.email || null, name: user.name || null };
      
      // Track user login locally
      trackUserLogin(user.name, user.email);
      
      // Check if this user is an admin
      const adminLevel = isAdmin(user.email);
      if (adminLevel) {
        req.session.adminUser = {
          email: user.email,
          name: user.name || user.email,
          level: adminLevel,
          loginTime: new Date().toISOString()
        };
        console.log(`Admin detected: ${user.email} (${adminLevel})`);
      }
      // Determine and store user role at login to avoid permission races later
      try {
        // Ensure permissions file is synced into users.csv requested flags
        try { syncRequestedFlags(); } catch(e) {}
        const normalizedRole = getUserRole(user.email);
        req.session.userRole = normalizedRole || 'student';
        req.session.isTeacher = Boolean(normalizedRole === 'teacher' || req.session.adminUser);
      } catch (rerr) {
        console.warn('Failed to set session role on login:', rerr && rerr.message);
        req.session.userRole = 'student';
        req.session.isTeacher = Boolean(req.session.adminUser);
      }
      
      // derive a simple school label from email
      const deriveSchoolFromEmail = (email) => {
        if (!email || typeof email !== 'string') return { raw: null, nice: null };
        const parts = email.split('@');
        if (parts.length !== 2) return { raw: null, nice: null };
        const domain = parts[1].toLowerCase();
        // remove common subdomains like mail., accounts., webmail.
        const cleaned = domain.replace(/^mail\.|^accounts\.|^webmail\./, '');
        const labels = cleaned.split('.');

        let nice = null;
        if (labels.length >= 2) {
          const sld = labels[labels.length - 2];
          const name = sld.replace(/[-_]/g, ' ');
          if (name.length <= 3) {
            nice = name.toUpperCase();
          } else {
            // title-case
            nice = name.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
          }
          // if domain looks like an educational domain, append a common suffix when appropriate
          const tld = labels[labels.length - 1];
          if (tld === 'edu' && nice && !/university|college|school/i.test(nice)) {
            nice = `${nice} University`;
          }
        }

        // fallback: raw domain
        return { raw: domain, nice: nice || domain };
      };

      const schoolInfo = deriveSchoolFromEmail(req.session.user.email);
      req.session.school = schoolInfo.raw;
      req.session.schoolNice = schoolInfo.nice;

      // compute cleaned domain for minimal display: remove edu/std and two-letter labels
      const computeCleanDomain = (domain) => {
        if (!domain || typeof domain !== 'string') return null;
        const labels = domain.split('.').filter(Boolean);
        const filtered = labels.filter(l => {
          const low = l.toLowerCase();
          if (low === 'edu' || low === 'std') return false;
          if (/^[a-z]{2}$/.test(low)) return false; // remove two-letter country/state codes
          return true;
        });
        if (filtered.length === 0) return null;
        return filtered.join('.');
      };

      const cleanedDomain = computeCleanDomain(schoolInfo.raw) || schoolInfo.raw || null;
      req.session.schoolDomain = cleanedDomain;

      // update persistent schools file to track multiple users from same domain
      try {
        updateSchoolRecord(cleanedDomain);
      } catch (uerr) {
        console.warn('Failed to update school record:', uerr && uerr.message);
      }

      // Ensure user profile exists in S3 and set flag if profile needs completion
      try {
        const email = req.session.user.email;
        const name = req.session.user.name || '';
        const adminLevel = isAdmin(email);
        // SECURITY: do not create or store admin profiles in S3
        if (!adminLevel) {
          // create default files if missing
          await ensureUserProfileInS3(email, name);

          // Fetch profile.json to determine if user needs to fill details
          let needsProfile = false;
          try {
            const prefix = makeUserFolderPrefix(email, name);
            const resp = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: prefix + 'profile.json' }));
            const profile = JSON.parse(await streamToString(resp.Body) || '{}');
            // If interests empty, name missing, or years_experience null => prompt user
            if (!profile || (!profile.interests || profile.interests.length === 0) || !profile.name || profile.years_experience === null) {
              needsProfile = true;
            }
          } catch (e) {
            needsProfile = true;
          }
          req.session.needsProfile = needsProfile;
        } else {
          req.session.needsProfile = false;
        }
      } catch (perr) {
        console.warn('Profile check/create failed:', perr && perr.message);
      }
      // Check for any approved/denied teacher requests and set one-time session decision
      try {
        checkAndSetUserDecision(req);
      } catch (e) {
        console.warn('Failed to set user decision:', e && e.message);
      }
    } catch (uerr) {
      console.warn('Failed to fetch userinfo:', uerr && uerr.message);
    }

    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      }
      res.redirect("/video.html?authed=1");
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Authentication failed");
  }
});

// === ADMIN AUTHENTICATION ROUTES ===

// Admin login with email/password
app.post("/auth/admin/login", express.json(), async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password required' });
    }
    
    // Check if email is in admin list
    const adminLevel = isAdmin(email);
    if (!adminLevel) {
      return res.status(401).json({ ok: false, error: 'Invalid admin credentials' });
    }
    
    const passwordOk = await verifyAdminPassword(password);
    if (!passwordOk) {
      return res.status(401).json({ ok: false, error: 'Invalid admin credentials' });
    }
    
    // Set admin session
    req.session.adminUser = {
      email: email,
      level: adminLevel,
      loginTime: new Date().toISOString()
    };
    // Also set session user role so front-end checks work consistently
    req.session.user = { email };
    req.session.userRole = 'admin';
    req.session.isTeacher = true;
    
    req.session.save((err) => {
      if (err) {
        console.error('Admin session save error:', err);
        return res.status(500).json({ ok: false, error: 'Session error' });
      }
      try {
        console.log('Admin login successful:', {
          email,
          level: adminLevel,
          sid: req.sessionID,
          hasAdminUser: Boolean(req.session.adminUser),
        });
      } catch (e) {
        console.warn('Admin login log failed:', e && e.message);
      }
      res.json({ ok: true, level: adminLevel });
    });
    
  } catch (err) {
    console.error('Admin login error:', err);
    if (err && err.message === 'admin_password_not_configured') {
      return res.status(500).json({ ok: false, error: 'Admin password is not configured' });
    }
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Admin login with Google (separate from regular user flow)
app.get("/auth/google/admin", (req, res) => {
  const scopes = [
    "openid",
    "email",
    "profile",
  ];
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: scopes,
    prompt: "consent",
    state: "admin_login" // Mark this as admin login
  });
  res.redirect(url);
});

// Admin Google callback
app.get("/auth/google/admin/callback", async (req, res) => {
  try {
    const { code } = req.query;
    const { tokens } = await oauth2Client.getToken(code);
    
    // Get user info from Google
    const tempClient = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    tempClient.setCredentials(tokens);
    const oauth2 = google.oauth2({ auth: tempClient, version: "v2" });
    const userinfoRes = await oauth2.userinfo.get();
    const user = userinfoRes.data || {};
    const email = user.email;
    
    // Check if this email is an admin
    const adminLevel = isAdmin(email);
    if (!adminLevel) {
      return res.status(403).send(`
        <html>
          <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>Access Denied</h1>
            <p>Your email (${email}) is not authorized as an admin.</p>
            <a href="/admin_login.html">Back to Login</a>
          </body>
        </html>
      `);
    }
    
    // Persist tokens for Drive actions
    try {
      oauth2Client.setCredentials(tokens);
      req.session.tokens = tokens;
      fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
    } catch (tokenErr) {
      console.warn('Failed to persist admin OAuth tokens:', tokenErr && tokenErr.message);
    }

    // Ensure Drive folder exists for uploads
    try {
      const driveClient = google.drive({ version: "v3", auth: oauth2Client });
      const folderId = await getOrCreateAppFolder(driveClient);
      if (folderId) req.session.appFolderId = folderId;
    } catch (driveErr) {
      console.warn('Failed to prepare Drive folder for admin:', driveErr && driveErr.message);
    }

    // Track login like regular OAuth flow
    try { trackUserLogin(user.name, email); } catch (e) { console.warn('Admin login tracking failed:', e && e.message); }

    // Set admin session metadata before saving
    req.session.adminUser = {
      email: email,
      name: user.name || email,
      level: adminLevel,
      loginTime: new Date().toISOString()
    };
    req.session.user = { email, name: user.name || email };
    req.session.userRole = 'admin';
    req.session.isTeacher = true;
    
    req.session.save((err) => {
      if (err) {
        console.error('Admin session save error:', err);
      }
      console.log(`Admin Google login successful: ${email} (${adminLevel})`);
      res.redirect("/admin/dashboard.html");
    });
    
  } catch (error) {
    console.error('Admin Google auth error:', error);
    res.status(500).send("Admin authentication failed");
  }
});

// Admin status check
app.get("/admin/status", (req, res) => {
  refreshSessionAuthFlags(req);
  try {
    console.log('ADMIN STATUS CHECK:', {
      sid: req.sessionID,
      hasAdminUser: Boolean(req.session && req.session.adminUser),
      adminEmail: req.session && req.session.adminUser && req.session.adminUser.email,
      cookieHeader: req.headers && req.headers.cookie,
    });
  } catch (e) {
    console.warn('Admin status log failed:', e && e.message);
  }
  const adminUser = req.session.adminUser;
  if (adminUser) {
    return res.json({
      isAdmin: true,
      email: adminUser.email,
      level: adminUser.level,
      name: adminUser.name || adminUser.email
    });
  }
  res.json({ isAdmin: false });
});

// Admin logout
app.post("/admin/logout", (req, res) => {
  const email = req.session.adminUser?.email;
  const tokens = req.session.tokens;
  
  try {
    // Revoke OAuth tokens
    if (tokens) {
      const client = buildAuthedClient(tokens);
      client.revokeCredentials().catch(err => console.warn('Token revoke failed:', err));
    }
  } catch (error) {
    console.warn('Error revoking tokens on logout:', error);
  }
  
  try {
    // Clear global oauth2Client state completely
    oauth2Client.setCredentials({});
    oauth2Client.credentials = {};
    
    // Delete token file
    if (fs.existsSync(TOKEN_PATH)) {
      fs.unlinkSync(TOKEN_PATH);
    }
  } catch (error) {
    console.warn('Error clearing oauth2Client:', error);
  }
  
  // Destroy session
  req.session.destroy((err) => {
    if (err) {
      // Treat missing session file (ENOENT) as non-fatal — session already removed
      if (err.code === 'ENOENT' || (err.message && String(err.message).includes('ENOENT'))) {
        console.warn('Admin logout: session file not found (treated as already removed)');
        console.log(`Admin logout: ${email} - All credentials cleared`);
        return res.json({ ok: true });
      }
      console.error('Admin logout error:', err);
      return res.status(500).json({ ok: false });
    }
    console.log(`Admin logout: ${email} - All credentials cleared`);
    res.json({ ok: true });
  });
});

// Middleware to protect admin routes
const ensureAdmin = (req, res, next) => {
  refreshSessionAuthFlags(req);
  if (req.session.adminUser) {
    return next();
  }
  try {
    console.warn('ensureAdmin blocked request — no admin session present for ip:', req.ip, 'user:', req.session && req.session.user && req.session.user.email);
  } catch (e) {}
  res.status(401).json({ error: 'admin_auth_required' });
};

// Middleware to ensure super admin
const ensureSuperAdmin = (req, res, next) => {
  if (req.session.adminUser && req.session.adminUser.level === 'super_admin') {
    return next();
  }
  res.status(403).json({ error: 'super_admin_required' });
};

// Report whether the server currently has Drive credentials.
app.get("/status", (req, res) => {
  refreshSessionAuthFlags(req);
  const creds = req.session.tokens || oauth2Client.credentials;
  const authenticated = Boolean(
    creds && (creds.access_token || creds.refresh_token)
  );
  console.log("server status authenticated:", authenticated);
  // include minimal user info when available
  const user = req.session.user || null;
  const school = req.session.school || null;
  const schoolNice = req.session.schoolNice || null;
  const schoolDomain = req.session.schoolDomain || null;
  
  // Get admin status from session (already set during OAuth callback)
  const adminUser = req.session.adminUser || null;
  const isAdmin = Boolean(adminUser);
  const adminLevel = adminUser ? adminUser.level : null;
  const roleFromPerms = (req.session && req.session.user && req.session.user.email)
    ? getUserRole(req.session.user.email)
    : 'student';
  const isTeacherRole = Boolean(roleFromPerms === 'teacher' || isAdmin);
  const effectiveRole = isAdmin ? 'admin' : (roleFromPerms || 'student');
  try {
    if (req.session) {
      req.session.userRole = effectiveRole;
      req.session.isTeacher = isTeacherRole;
    }
  } catch (e) {
    // ignore
  }
  
  // include school count from file if available
  let schoolCount = null;
  try {
    const schools = readSchoolsFile();
    if (schoolDomain && schools[schoolDomain]) schoolCount = schools[schoolDomain].count || null;
  } catch (e) {
    // ignore
  }
  res.json({ 
    authenticated, 
    user, 
    school, 
    schoolNice, 
    schoolDomain, 
    schoolCount,
    isAdmin,
    adminLevel
    ,needsProfile: Boolean(req.session && req.session.needsProfile)
    ,role: effectiveRole || 'student'
    ,isTeacher: isTeacherRole
    ,decision: (req.session && req.session.requestDecision) || null
  });
  // clear one-time decision after exposing it
  try { if (req.session) { delete req.session.requestDecision; req.session.save && req.session.save(()=>{}); } } catch(e){}
});

// === ADMIN-ONLY ENDPOINTS ===

// Get all users from schools file + individual email tracking (admin only)
app.get('/admin/users', ensureAdmin, async (req, res) => {
  try {
    console.log('GET /admin/users - Loading user data from LOCAL CSV files...');
    
    // PRIMARY: Sync requested flags then load from LOCAL files
    try { syncRequestedFlags(); } catch(e) { console.warn('syncRequestedFlags failed', e && e.message); }
    const users = readUsersCSV();
    const admins = readAdminsActivity();
    const permissions = readUserPermissions();
    const schools = readSchoolsFile();
    
    console.log(`✓ Loaded from local: ${users.length} users, ${admins.length} admins`);
    
    const schoolList = Object.keys(schools).map(domain => ({
      domain,
      count: schools[domain].count,
      lastSeen: schools[domain].lastSeen
    }));
    
    const userList = users.map(user => ({
      name: user.name,
      email: user.email,
      first_login: user.first_login,
      last_login: user.last_login,
      login_count: user.login_count,
      requested: Boolean(user.requested)
    }));
    
    res.json({
      ok: true,
      schools: schoolList,
      users: userList,
      admins: admins,
      permissions: permissions,
      totalSchools: schoolList.length,
      totalUsers: userList.length,
      totalAdmins: admins.length,
      dataSource: 'Local CSV Files'
    });
    
    // BACKUP: Sync to Drive in background (non-blocking)
    if (req.session && req.session.tokens) {
      setImmediate(async () => {
        try {
          const drive = getDriveForRequest(req);
          if (drive) {
            await Promise.race([
              backupAllFilesToDrive(drive),
              new Promise((_, reject) => setTimeout(() => reject(new Error('sync timeout')), 5000))
            ]);
            console.log('Background Drive sync completed');
          }
        } catch (err) {
          console.warn('Background sync failed (non-blocking):', err.message);
        }
      });
    }
    
  } catch (err) {
    console.error('Admin users endpoint error:', err);
    res.status(500).json({ ok: false, error: err.message, dataSource: 'error' });
  }
});

// Get user permissions
app.get('/admin/user-permissions', ensureAdmin, (req, res) => {
  try {
    console.log('GET /admin/user-permissions - Loading permissions...');
    
    const permFile = path.join(DATA_DIR, 'user_permissions.csv');
    let permissions = [];
    
    if (!fs.existsSync(permFile)) {
      console.log('Permissions file does not exist, creating empty...');
      fs.writeFileSync(permFile, 'email,role,notes\n', 'utf8');
    }
    
    const content = fs.readFileSync(permFile, 'utf8');
    const lines = content.trim().split('\n');
    permissions = lines.slice(1).map(line => {
      const [email, role, notes] = line.split(',');
      return { email, role: role || 'student', notes: notes || '' };
    }).filter(p => p.email);
    
    console.log(`Loaded ${permissions.length} permission entries`);
    res.json({ ok: true, permissions });
  } catch (err) {
    console.error('Error reading permissions:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Return teacher role requests (from interests submissions) that are not yet approved
app.get('/admin/teacher-requests', ensureAdmin, (req, res) => {
  try {
    const permissions = readUserPermissions();
    const list = readInterestsFile();
    const users = readUsersCSV();
    const deduped = new Map();

    (permissions || []).forEach(p => {
      if (!p || !p.email) return;
      if (normalizeRole(p.role) !== 'requested') return;
      const key = normalizeEmail(p.email);
      if (!key || deduped.has(key)) return;
      deduped.set(key, { email: p.email, name: '', notes: p.notes || '' });
    });

    (list || []).forEach(entry => {
      if (!entry || !entry.email) return;
      const role = normalizeRole(entry.role);
      const status = String(entry.status || '').trim().toLowerCase() || 'pending';
      if (role !== 'teacher' || (status !== 'pending' && status !== 'requested')) return;
      const key = normalizeEmail(entry.email);
      if (deduped.has(key)) return;
      deduped.set(key, { email: entry.email, name: entry.name || '', notes: entry.message || entry.notes || '' });
    });

    // Also surface any users in users.csv with requested=true that are not yet
    // reflected in permissions/interests as approved/denied teacher roles.
    (users || []).forEach(u => {
      if (!u || !u.email) return;
      if (!u.requested) return;
      const key = normalizeEmail(u.email);
      if (!key || deduped.has(key)) return;
      // Skip if already a teacher/admin by permissions
      const role = getUserRole(u.email);
      if (role === 'teacher' || role === 'admin' || role === 'super_admin') return;
      deduped.set(key, { email: u.email, name: u.name || '', notes: 'Requested in users.csv' });
    });

    res.json({ ok: true, requests: Array.from(deduped.values()) });
  } catch (err) {
    console.error('Error reading teacher requests:', err && err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Approve a teacher request: add to user_permissions.csv
app.post('/admin/approve-teacher', ensureAdmin, express.json(), (req, res) => {
  try {
    const { email, name, notes } = req.body || {};
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) return res.status(400).json({ ok: false, error: 'email_required' });

    const permissions = readUserPermissions();
    const idx = permissions.findIndex(p => normalizeEmail(p.email) === normalizedEmail);
    if (idx === -1) {
      permissions.push({ email: String(email).trim(), role: 'teacher', notes: notes || '' });
    } else {
      permissions[idx].role = 'teacher';
      permissions[idx].notes = notes || permissions[idx].notes || '';
      if (!permissions[idx].email) permissions[idx].email = String(email).trim();
    }

    // Write back
    const permFile = path.join(DATA_DIR, 'user_permissions.csv');
    const header = 'email,role,notes\n';
    const rows = permissions.map(p => `${p.email},${p.role},${(p.notes || '').replace(/,/g, ';')}`).join('\n');
    fs.writeFileSync(permFile, header + rows, 'utf8');

    // Also update any permissions entries that were 'requested' to 'teacher' (already done above), and mark any interest log entries as approved
    try {
      const list = readInterestsFile();
      const updated = list.map(it => {
        if (it && normalizeEmail(it.email) === normalizedEmail && normalizeRole(it.role) === 'teacher') {
          return { ...it, status: 'approved', approver: (req.session && req.session.adminUser && req.session.adminUser.email) || 'admin', notified: false, decidedAt: new Date().toISOString() };
        }
        return it;
      });
      writeInterestsFile(updated);
    } catch (e) {
      console.warn('Failed to mark interest entries as approved:', e && e.message);
    }

    // Mark related interest entries as approved and unnotified so user sees one-time notification
    try {
      const list = readInterestsFile();
      const updated = list.map(it => {
        if (it && normalizeEmail(it.email) === normalizedEmail && normalizeRole(it.role) === 'teacher') {
          return { ...it, status: 'approved', approver: (req.session && req.session.adminUser && req.session.adminUser.email) || 'admin', notified: false, decidedAt: new Date().toISOString() };
        }
        return it;
      });
      writeInterestsFile(updated);
    } catch (e) {
      console.warn('Failed to mark interest entries as approved:', e && e.message);
    }

    console.log(`Approved teacher: ${email}`);
    // background backup to Drive if available
    if (req.session && req.session.tokens) {
      setImmediate(async () => {
        try {
          const drive = getDriveForRequest(req);
          if (drive) {
            await backupAllFilesToDrive(drive);
            console.log('Permissions update backed up to Drive');
          }
        } catch (err) {
          console.warn('Failed to backup permissions:', err.message);
        }
      });
    }

      // Clear requested flag on approve so UI hides approve/deny actions
      try {
        const users = readUsersCSV();
        const ui = users.findIndex(u => normalizeEmail(u.email) === normalizedEmail);
        if (ui !== -1) {
          users[ui].requested = false;
          writeUsersCSV(users);
        }
      } catch (ue) {
        console.warn('Failed to clear requested flag after approve:', ue && ue.message);
      }

      res.json({ ok: true });
  } catch (err) {
    console.error('/admin/approve-teacher error', err && err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Deny a teacher request
app.post('/admin/deny-teacher', ensureAdmin, express.json(), (req, res) => {
  try {
    const { email, name, reason } = req.body || {};
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) return res.status(400).json({ ok: false, error: 'email_required' });

    const list = readInterestsFile();
    const updated = list.map(it => {
      if (it && normalizeEmail(it.email) === normalizedEmail && normalizeRole(it.role) === 'teacher') {
        return { ...it, status: 'denied', reason: reason || '', notified: false };
      }
      return it;
    });
    writeInterestsFile(updated);

    console.log(`Denied teacher request: ${email}`);
    // Clear requested flag on deny so UI hides actions
    try {
      const users = readUsersCSV();
      const ui = users.findIndex(u => normalizeEmail(u.email) === normalizedEmail);
      if (ui !== -1) {
        users[ui].requested = false;
        writeUsersCSV(users);
      }
    } catch (ue) {
      console.warn('Failed to clear requested flag after deny:', ue && ue.message);
    }
    // Remove any 'requested' entry from user_permissions.csv for this email
    try {
      const perms = readUserPermissions();
      const filtered = (perms || []).filter(p => normalizeEmail(p.email) !== normalizedEmail || normalizeRole(p.role) !== 'requested');
      const permFile = path.join(DATA_DIR, 'user_permissions.csv');
      const header = 'email,role,notes\n';
      const rows = filtered.map(p => `${p.email},${p.role},${(p.notes || '').replace(/,/g,';')}`).join('\n');
      fs.writeFileSync(permFile, header + rows, 'utf8');
    } catch (pe) {
      console.warn('Failed to remove requested permission entry on deny:', pe && pe.message);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('/admin/deny-teacher error', err && err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Update user data and permissions
app.post('/admin/update-user', ensureAdmin, async (req, res) => {
  try {
    const { email, name, role, notes } = req.body;
    if (!email) return res.status(400).json({ ok: false, error: 'email_required' });
    
    // Update user in CSV
    const users = readUsersCSV();
    const userIndex = users.findIndex(u => u.email.toLowerCase() === email.toLowerCase());
    
    if (userIndex !== -1) {
      if (name) users[userIndex].name = name;
      writeUsersCSV(users);
    }
    
    // Update permissions
    const permissions = readUserPermissions();
    const permIndex = permissions.findIndex(p => p.email.toLowerCase() === email.toLowerCase());
    
    if (role && role.toLowerCase() === 'student') {
      // If changing to student (default), remove from permissions entirely
      if (permIndex !== -1) {
        permissions.splice(permIndex, 1);
        console.log(`Removed ${email} from permissions (changed to default student role)`);
      }
    } else if (role) {
      // For non-student roles (teacher, etc), add/update in permissions
      if (permIndex !== -1) {
        permissions[permIndex].role = normalizeRole(role);
        permissions[permIndex].notes = notes || '';
      } else {
        permissions.push({ email: String(email).trim(), role: normalizeRole(role), notes: notes || '' });
      }
    }
    
    // Write permissions back to local
    const permFile = path.join(DATA_DIR, 'user_permissions.csv');
    const header = 'email,role,notes\n';
    const rows = permissions.map(p => `${p.email},${p.role},${(p.notes || '').replace(/,/g, ';')}`).join('\n');
    fs.writeFileSync(permFile, header + rows, 'utf8');
    
    console.log(`Admin updated user: ${email} (role: ${role})`);
    
    // Backup to Drive in background
    if (req.session && req.session.tokens) {
      setImmediate(async () => {
        try {
          const drive = getDriveForRequest(req);
          if (drive) {
            await backupAllFilesToDrive(drive);
            console.log('User update backed up to Drive');
          }
        } catch (err) {
          console.warn('Failed to backup to Drive:', err.message);
        }
      });
    }
    
    res.json({ ok: true });
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Delete user (remove from users.csv, permissions, and related request data)
app.post('/admin/delete-user', ensureAdmin, async (req, res) => {
  try {
    const { email } = req.body || {};
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) return res.status(400).json({ ok: false, error: 'email_required' });

    // Delete from users CSV (login history + requested flag)
    try {
      const users = readUsersCSV();
      const filteredUsers = (users || []).filter(u => normalizeEmail(u.email) !== normalizedEmail);
      writeUsersCSV(filteredUsers);
    } catch (e) {
      console.warn('delete-user: failed to update users.csv:', e && e.message);
    }

    // Delete all explicit permissions for this user (teacher/requested/etc.)
    try {
      const permissions = readUserPermissions();
      const filteredPerms = (permissions || []).filter(p => normalizeEmail(p.email) !== normalizedEmail);
      const permFile = path.join(DATA_DIR, 'user_permissions.csv');
      const header = 'email,role,notes\n';
      const rows = filteredPerms.map(p => `${p.email},${p.role},${(p.notes || '').replace(/,/g, ';')}`).join('\n');
      fs.writeFileSync(permFile, header + rows, 'utf8');
    } catch (e) {
      console.warn('delete-user: failed to update user_permissions.csv:', e && e.message);
    }

    // Remove any interests/teacher-requests for this email so they don't
    // continue to appear as pending after deletion.
    try {
      const interests = readInterestsFile();
      const filteredInterests = (interests || []).filter(it => normalizeEmail(it && it.email) !== normalizedEmail);
      writeInterestsFile(filteredInterests);
    } catch (e) {
      console.warn('delete-user: failed to update interests.json:', e && e.message);
    }

    // Optionally attempt to remove from schools.json if users are tracked there
    try {
      const schools = readSchoolsFile();
      let modified = false;
      Object.keys(schools || {}).forEach(domain => {
        const schoolUsers = schools[domain].users || [];
        const before = schoolUsers.length;
        schools[domain].users = schoolUsers.filter(u => normalizeEmail(u) !== normalizedEmail);
        if (schools[domain].users.length < before) modified = true;
      });
      if (modified) {
        fs.writeFileSync(SCHOOLS_FILE, JSON.stringify(schools, null, 2), 'utf8');
      }
    } catch (e) {
      console.warn('delete-user: failed to update schools.json:', e && e.message);
    }

    console.log(`Admin deleted user and cleared data: ${normalizedEmail}`);

    // Backup to Drive in background
    if (req.session && req.session.tokens) {
      setImmediate(async () => {
        try {
          const drive = getDriveForRequest(req);
          if (drive) {
            await backupAllFilesToDrive(drive);
            console.log('User deletion backed up to Drive');
          }
        } catch (err) {
          console.warn('Failed to backup to Drive:', err.message);
        }
      });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get admin list (super admin only)
app.get('/admin/list', ensureSuperAdmin, (req, res) => {
  try {
    const admins = readAdminsCSV();
    res.json({ ok: true, admins });
  } catch (err) {
    console.error('Admin list endpoint error:', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Accept interest submissions from the front-end CTA form
app.post('/interest', async (req, res) => {
  try {
    const { name, email, role, message } = req.body || {};
    if (!email || !role) return res.status(400).json({ ok: false, error: 'email and role required' });

    // Prevent admins from submitting interest/role requests (security)
    try {
      const admins = readAdminsCSV();
      const isAdminUser = admins.some(a => String(a.email || '').toLowerCase() === String(email).toLowerCase());
      if (isAdminUser) {
        console.warn('Admin attempted /interest submission, ignored:', email);
        return res.status(403).json({ ok: false, error: 'admins_cannot_request' });
      }
    } catch (e) {
      // If admin read fails, continue but log
      console.warn('Failed to check admin status for /interest:', e && e.message);
    }

    const list = readInterestsFile();
    const entry = {
      id: Date.now().toString(36) + Math.floor(Math.random()*1000),
      name: (name||'').trim(),
      email: (email||'').trim().toLowerCase(),
      role: (role||'').trim().toLowerCase(),
      message: (message||'').trim(),
      status: 'pending',
      notified: false,
      ip: req.ip,
      createdAt: new Date().toISOString()
    };
    list.push(entry);
    writeInterestsFile(list);

    // If the user requests teacher privileges, update local permissions CSV (role = 'requested')
    if (String(entry.role).toLowerCase() === 'teacher') {
      try {
        const permissions = readUserPermissions();
        const lower = String(entry.email).toLowerCase();
        const idx = permissions.findIndex(p => String(p.email || '').toLowerCase() === lower);
        if (idx === -1) {
          permissions.push({ email: entry.email, role: 'requested', notes: entry.message || '' });
        } else {
          const existingRole = normalizeRole(permissions[idx].role);
          permissions[idx].role = existingRole === 'teacher' ? 'teacher' : 'requested';
          permissions[idx].notes = permissions[idx].notes || entry.message || '';
        }

        // Write permissions locally
        try {
          ensureDataDir();
          const permFile = path.join(DATA_DIR, 'user_permissions.csv');
          const header = 'email,role,notes\n';
          const rows = permissions.map(p => `${p.email},${p.role},${(p.notes || '').replace(/,/g,';')}`).join('\n');
          fs.writeFileSync(permFile, header + rows, 'utf8');
        } catch (we) {
          console.warn('Failed to write permissions locally for request:', we && we.message);
        }

        // Try to sync permissions to Drive using server-side OAuth if available
        try {
          if (oauth2Client && oauth2Client.credentials && (oauth2Client.credentials.access_token || oauth2Client.credentials.refresh_token)) {
            const driveClient = google.drive({ version: 'v3', auth: oauth2Client });
            const folderId = await getOrCreateSimTkBackupFolder(driveClient);
            if (folderId) {
              const permFileId = await getOrCreateBackupFile(driveClient, folderId, 'user_permissions.csv');
              const content = fs.readFileSync(path.join(DATA_DIR, 'user_permissions.csv'), 'utf8');
              await writeBackupFile(driveClient, permFileId, content);
            }
          }
        } catch (de) {
          console.warn('Drive sync of permissions failed:', de && de.message);
        }
      } catch (pe) {
        console.warn('Error handling permission update for interest request:', pe && pe.message);
      }
      // Also mark the user in users.csv as having requested teacher privileges
      try {
        const users = readUsersCSV();
        const lower = String(entry.email).toLowerCase();
        const uidx = users.findIndex(u => String(u.email || '').toLowerCase() === lower);
        const now = new Date().toISOString();
        if (uidx === -1) {
          users.push({ name: entry.name || entry.email, email: entry.email, first_login: now, last_login: now, login_count: 0, requested: true });
        } else {
          users[uidx].requested = true;
        }
        writeUsersCSV(users);
      } catch (ue) {
        console.warn('Failed to mark user requested flag:', ue && ue.message);
      }
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /interest error', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Helper: process decision notifications for a user (one-time)
const checkAndSetUserDecision = (req) => {
  try {
    if (!req || !req.session || !req.session.user || !req.session.user.email) return;
    const email = String(req.session.user.email).toLowerCase();
    const list = readInterestsFile();
    let found = null;
    // Find newest unnotified decision for this email
    for (let i = list.length - 1; i >= 0; i--) {
      const it = list[i];
      if (!it || !it.email) continue;
      if (String(it.email).toLowerCase() !== email) continue;
      if (it.status === 'approved' && !it.notified) {
        found = { type: 'approved', entry: it };
        break;
      }
      if (it.status === 'denied' && !it.notified) {
        found = { type: 'denied', entry: it };
        break;
      }
    }
    if (found) {
      const entry = found.entry;
      if (found.type === 'approved') {
        req.session.requestDecision = { type: 'approved', message: 'Your teacher request has been approved.' };
      } else {
        const reason = entry.reason || '';
        req.session.requestDecision = { type: 'denied', message: `Your teacher request was denied. ${reason}`.trim() };
      }
      // mark related entries as notified
      const updated = list.map(it => {
        if (it && it.email && String(it.email).toLowerCase() === email && (it.status === 'approved' || it.status === 'denied')) {
          return { ...it, notified: true };
        }
        return it;
      });
      writeInterestsFile(updated);
    }
  } catch (e) {
    console.warn('checkAndSetUserDecision error', e && e.message);
  }
};

// Q&A: accept student questions (auth required - store on Google Drive)
app.post('/questions', ensureAuthed, async (req, res) => {
  try {
    const { name, email, question } = req.body || {};
    if (!question) return res.status(400).json({ ok: false, error: 'question required' });
    
    const drive = getDriveForRequest(req);
    if (!drive) {
      return res.status(401).json({ error: "not_authenticated" });
    }
    
    // Ensure app folder ID exists
    if (!req.session.appFolderId) {
      console.error('POST /questions: No appFolderId in session');
      return res.status(500).json({ ok: false, error: 'app_folder_not_found' });
    }
    
    // Get or create Q&A file inside app folder
    let qnaFileId = req.session.qnaFileId;
    if (!qnaFileId) {
      qnaFileId = await getOrCreateQnAFile(drive, req.session.appFolderId);
      if (qnaFileId) {
        req.session.qnaFileId = qnaFileId;
      }
    }
    
    if (!qnaFileId) {
      return res.status(500).json({ ok: false, error: 'could_not_create_file' });
    }
    
    const entry = {
      name: (name || req.session.user?.name || '').trim(),
      email: (email || req.session.user?.email || '').trim().toLowerCase(),
      question: (question || '').trim()
    };
    
    const appended = await appendToQnAFile(drive, qnaFileId, entry);
    if (!appended) {
      return res.status(500).json({ ok: false, error: 'failed_to_save' });
    }
    
    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /questions error', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Q&A: list recent questions (auth required - fetch from Google Drive)
app.get('/questions', ensureAuthed, async (req, res) => {
  try {
    const drive = getDriveForRequest(req);
    if (!drive) {
      return res.status(401).json({ error: "not_authenticated" });
    }
    
    // Ensure app folder ID exists
    if (!req.session.appFolderId) {
      console.error('GET /questions: No appFolderId in session');
      return res.status(500).json({ ok: false, error: 'app_folder_not_found' });
    }
    
    // Get or create Q&A file inside app folder
    let qnaFileId = req.session.qnaFileId;
    if (!qnaFileId) {
      qnaFileId = await getOrCreateQnAFile(drive, req.session.appFolderId);
      if (qnaFileId) {
        req.session.qnaFileId = qnaFileId;
      }
    }
    
    if (!qnaFileId) {
      return res.status(500).json({ ok: false, error: 'could_not_create_file' });
    }
    
    const questions = await readQnAFile(drive, qnaFileId);
    return res.json({ ok: true, items: questions });
  } catch (err) {
    console.error('GET /questions error', err && err.message);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Q&A: delete a question (only if posted within 30 seconds) - Google Drive version
app.route('/questions/:id')
  .delete(ensureAuthed, async (req, res) => {
    try {
      const { id } = req.params;
      const now = Date.now();
      
      const drive = getDriveForRequest(req);
      if (!drive) {
        return res.status(401).json({ error: "not_authenticated" });
      }
      
      // Ensure app folder ID exists
      if (!req.session.appFolderId) {
        return res.status(500).json({ ok: false, error: 'app_folder_not_found' });
      }
      
      // Get Q&A file
      let qnaFileId = req.session.qnaFileId;
      if (!qnaFileId) {
        qnaFileId = await getOrCreateQnAFile(drive, req.session.appFolderId);
        if (qnaFileId) {
          req.session.qnaFileId = qnaFileId;
        }
      }
      
      if (!qnaFileId) {
        return res.status(500).json({ ok: false, error: 'could_not_find_file' });
      }
      
      // Read file content
      const res_get = await drive.files.get(
        { fileId: qnaFileId, alt: "media" },
        { responseType: "stream" }
      );
      let content = '';
      await new Promise((resolve, reject) => {
        res_get.data.on('data', chunk => (content += chunk));
        res_get.data.on('end', resolve);
        res_get.data.on('error', reject);
      });
      
      // Parse questions to find the one to delete
      const questions = await readQnAFile(drive, qnaFileId);
      const questionIndex = questions.findIndex(q => q.id === id);
      
      if (questionIndex === -1) {
        return res.status(404).json({ ok: false, error: 'question_not_found' });
      }
      
      // Check if within 30 seconds
      const question = questions[questionIndex];
      const createdTime = new Date(question.createdAt).getTime();
      const ageSeconds = (now - createdTime) / 1000;
      
      if (ageSeconds > 30) {
        return res.status(403).json({ ok: false, error: 'deletion_window_closed' });
      }
      
      // Remove the question lines from content
      const lines = content.split('\n');
      const startLine = question.startLine;
      const endLine = question.endLine;
      
      // Remove lines for this question (including the trailing blank line)
      lines.splice(startLine, endLine - startLine + 2);
      
      // Rebuild content
      const newContent = lines.join('\n');
      
      // Update file on Drive
      await drive.files.update({
        fileId: qnaFileId,
        media: {
          mimeType: "text/plain",
          body: newContent,
        },
      });
      
      console.log(`Deleted question ${id} from file`);
      return res.json({ ok: true });
    } catch (err) {
      console.error('DELETE /questions/:id error', err && err.message);
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

// Serve the saved interests as a plain text file for local viewing
app.get('/interests.txt', (req, res) => {
  try {
    ensureDataDir();
    if (!fs.existsSync(INTERESTS_FILE)) {
      return res.type('text').send('No interest entries yet.');
    }
    const raw = fs.readFileSync(INTERESTS_FILE, 'utf8') || '[]';
    const list = JSON.parse(raw);
    // Only expose pending/requested teacher entries so admin fallback UI
    // does not treat approved/denied requests as still pending.
    const filtered = (list || []).filter(it => {
      if (!it || !it.email) return false;
      const role = normalizeRole(it.role);
      const status = String(it.status || '').trim().toLowerCase() || 'pending';
      if (role !== 'teacher') return false;
      return status === 'pending' || status === 'requested';
    });
    const lines = filtered.map(it => {
      return [`ID: ${it.id}`, `Name: ${it.name || ''}`, `Email: ${it.email || ''}`, `Role: ${it.role || ''}`, `Message: ${it.message || ''}`, `IP: ${it.ip || ''}`, `Time: ${it.createdAt || ''}`].join(' | ');
    });
    return res.type('text').send(lines.join('\n') || 'No interest entries yet.');
  } catch (err) {
    console.error('GET /interests.txt error', err && err.message);
    return res.status(500).type('text').send('Failed to read interests');
  }
});

// Revoke credentials and remove the local token cache.
app.post("/logout", async (req, res) => {
  console.log("logout called, clearing credentials");
  const tokens = req.session.tokens;
  try {
    if (tokens) {
      const client = buildAuthedClient(tokens);
      await client.revokeCredentials();
    }
  } catch (error) {
    console.error("Failed to revoke credentials", error);
  }
  
  // Clear oauth2Client credentials
  oauth2Client.setCredentials({});
  
  // Delete token file
  if (fs.existsSync(TOKEN_PATH)) {
    fs.unlinkSync(TOKEN_PATH);
  }
  // Ensure the user's school is recorded persistently even after logout.
  try {
    // Prefer cleaned domain stored in session, fallback to deriving from email.
    let domainToRecord = req.session && req.session.schoolDomain ? req.session.schoolDomain : null;
    if (!domainToRecord && req.session && req.session.user && req.session.user.email) {
      const parts = String(req.session.user.email || '').split('@');
      if (parts.length === 2) {
        const raw = parts[1].toLowerCase();
        // basic cleaning: remove common subdomains and drop short/country labels
        const cleaned = raw.replace(/^mail\.|^accounts\.|^webmail\./, '');
        const labels = cleaned.split('.').filter(Boolean);
        const filtered = labels.filter(l => {
          const low = l.toLowerCase();
          if (low === 'edu' || low === 'std') return false;
          if (/^[a-z]{2}$/.test(low)) return false;
          return true;
        });
        domainToRecord = filtered.join('.') || cleaned || raw;
      }
    }
    if (domainToRecord) {
      try {
        updateSchoolRecord(domainToRecord);
      } catch (uerr) {
        console.warn('Failed to persist school on logout:', uerr && uerr.message);
      }
    }
  } catch (e) {
    console.warn('Error while ensuring school persistence on logout', e && e.message);
  }

  req.session.destroy((destroyError) => {
    if (destroyError) {
      // If the underlying session file was already removed, consider logout successful.
      if (destroyError.code === 'ENOENT' || (destroyError.message && String(destroyError.message).includes('ENOENT'))) {
        console.warn('Logout: session file not found during destroy (treated as success)');
        return res.json({ ok: true });
      }
      console.error("Failed to destroy session", destroyError);
      return res.status(500).json({ ok: false });
    }
    res.json({ ok: true });
  });
});

// Upload a video file to Google Drive.
app.post("/upload", ensureAuthed, upload.single("video"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "missing_file" });
  }
  // Only allow Drive uploads for approved teachers or admins
  if (!hasTeacherPrivileges(req)) {
    console.warn('/upload denied: missing teacher/admin privileges', {
      sessionUser: req.session && req.session.user,
      sessionRole: req.session && req.session.userRole,
      adminUser: req.session && req.session.adminUser
    });
    return res.status(403).json({ error: 'teacher_role_required' });
  }

  try {
    const drive = getDriveForRequest(req);
    if (!drive) {
      console.warn('/upload: getDriveForRequest returned null; DRIVE_CONFIGURED=', DRIVE_CONFIGURED, 'session.tokens=', !!(req.session && req.session.tokens));
      return res.status(401).json({ error: "not_authenticated" });
    }
    
    // Get or create folder ID
    let folderId = req.session.appFolderId;
    if (!folderId) {
      folderId = await getOrCreateAppFolder(drive);
      if (folderId) {
        req.session.appFolderId = folderId;
      }
    }
    
    // Prefix Drive filenames with 'stm' to mark Google-uploaded files
    const requestBody = { name: `stm${req.file.originalname}` };
    if (folderId) {
      requestBody.parents = [folderId];
    }
    
    const response = await drive.files.create({
      requestBody,
      media: {
        mimeType: req.file.mimetype,
        body: bufferToStream(req.file.buffer),
      },
      fields: "id,name,createdTime",
    });

    res.json(response.data);
  } catch (error) {
    console.error('/upload error:', error && (error.message || error));
    if (isInsufficientScopeError(error)) {
      clearStoredTokens(req);
      return res.status(401).json({ error: 'insufficient_scope', action: '/auth/google' });
    }
    res.status(500).json({ error: "upload_failed" });
  }
});

// Upload a video file to AWS S3 (no Google auth required)
app.post("/upload-s3", s3UploadMiddleware.single("video"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "missing_file" });
  }
  if (!process.env.AWS_S3_BUCKET || !process.env.AWS_REGION) {
    return res.status(500).json({ error: "s3_not_configured" });
  }

  // Only allow uploads to reels for approved teachers or admins
  if (!hasTeacherPrivileges(req)) {
    return res.status(403).json({ error: 'teacher_role_required' });
  }
  // Place uploads inside per-user folder when available
  let Key;
  try {
    const email = req.session && req.session.user && req.session.user.email;
    const isAdminUser = Boolean(req.session && req.session.adminUser) || (email && isAdmin(email));
    if (isAdminUser) {
      // Avoid embedding admin email in S3 key for security
      Key = `admins/${Date.now()}-${req.file.originalname}`;
    } else if (req.session && req.session.user && req.session.user.email) {
      const prefix = makeUserFolderPrefix(req.session.user.email, req.session.user.name || '');
      Key = `${prefix}${Date.now()}-${req.file.originalname}`;
    } else {
      Key = `${Date.now()}-${req.file.originalname}`;
    }
  } catch (e) {
    Key = `${Date.now()}-${req.file.originalname}`;
  }
  try {
    const result = await uploadFile(req.file, { key: Key });
    return res.json({
      key: result.key,
      publicUrl: result.publicUrl,
      bucket: result.bucket,
      status: result.status,
    });
  } catch (err) {
    const status = err instanceof S3UploadError ? err.statusCode : 500;
    const errorCode = err instanceof S3UploadError ? err.code : "s3_upload_failed";
    console.error("S3 upload error:", err && err.message ? err.message : err);
    return res.status(status).json({ error: errorCode, message: err && err.message ? err.message : "s3_upload_failed" });
  }
});

// Upload multiple files to AWS S3.
app.post("/upload-s3-multiple", s3UploadMiddleware.array("files", 20), async (req, res) => {
  const files = Array.isArray(req.files) ? req.files : [];
  if (!files.length) {
    return res.status(400).json({ error: "missing_files" });
  }
  if (!process.env.AWS_S3_BUCKET || !process.env.AWS_REGION) {
    return res.status(500).json({ error: "s3_not_configured" });
  }
  if (!hasTeacherPrivileges(req)) {
    return res.status(403).json({ error: "teacher_role_required" });
  }

  let keyPrefix = "uploads";
  try {
    const email = req.session && req.session.user && req.session.user.email;
    const isAdminUser = Boolean(req.session && req.session.adminUser) || (email && isAdmin(email));
    if (isAdminUser) {
      keyPrefix = "admins";
    } else if (req.session && req.session.user && req.session.user.email) {
      keyPrefix = makeUserFolderPrefix(req.session.user.email, req.session.user.name || "").replace(/\/+$/, "");
    }
  } catch (e) {
    keyPrefix = "uploads";
  }

  try {
    const uploads = await uploadMultipleFiles(files, { keyPrefix });
    const hasFailures = uploads.some((u) => u.status === "failed");
    return res.status(hasFailures ? 207 : 200).json({ uploads });
  } catch (err) {
    const status = err instanceof S3UploadError ? err.statusCode : 500;
    const errorCode = err instanceof S3UploadError ? err.code : "s3_upload_failed";
    return res.status(status).json({ error: errorCode, message: err && err.message ? err.message : "s3_upload_failed" });
  }
});

// Delete an S3 object by key.
app.delete('/s3/object', async (req, res) => {
  try {
    const key = req.query && req.query.key ? String(req.query.key) : "";
    if (!key) return res.status(400).json({ error: "missing_key" });
    const result = await deleteFile(key);
    return res.json(result);
  } catch (err) {
    const status = err instanceof S3UploadError ? err.statusCode : 500;
    const errorCode = err instanceof S3UploadError ? err.code : "delete_failed";
    return res.status(status).json({ error: errorCode, message: err && err.message ? err.message : "delete_failed" });
  }
});

// GET current user's profile (from S3)
app.get('/user/profile', async (req, res) => {
  try {
    if (!req.session || !req.session.user || !req.session.user.email) return res.status(401).json({ error: 'not_authenticated' });
    if (!process.env.S3_BUCKET_NAME || !process.env.AWS_REGION || !s3) return res.status(500).json({ error: 's3_not_configured' });
    const prefix = makeUserFolderPrefix(req.session.user.email, req.session.user.name || '');
    const Key = prefix + 'profile.json';
    const resp = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key }));
    const profile = JSON.parse(await streamToString(resp.Body) || '{}');
    return res.json({ ok: true, profile });
  } catch (err) {
    console.warn('/user/profile get error', err && err.message);
    return res.status(404).json({ ok: false, error: 'profile_not_found' });
  }
});

// POST update user's profile (save to S3 as JSON and TXT)
app.post('/user/profile', express.json(), async (req, res) => {
  try {
    if (!req.session || !req.session.user || !req.session.user.email) return res.status(401).json({ error: 'not_authenticated' });
    if (!process.env.S3_BUCKET_NAME || !process.env.AWS_REGION || !s3) return res.status(500).json({ error: 's3_not_configured' });
    const { name, interests, years_experience, want_to_teach } = req.body || {};
    const normalizedInterests = Array.isArray(interests) ? interests.slice(0,3).map(String) : [];
    const profile = {
      name: String(name || req.session.user.name || ''),
      interests: normalizedInterests,
      years_experience: years_experience == null ? null : Number(years_experience),
      want_to_teach: Boolean(want_to_teach),
      updatedAt: new Date().toISOString()
    };

    const prefix = makeUserFolderPrefix(req.session.user.email, req.session.user.name || '');
    const Bucket = process.env.S3_BUCKET_NAME;
    await s3.send(new PutObjectCommand({ Bucket, Key: prefix + 'profile.json', Body: JSON.stringify(profile, null, 2), ContentType: 'application/json' }));

    const txt = `Name: ${profile.name}\nField of interest (up to 3): ${profile.interests.join(', ')}\nYears of experience: ${profile.years_experience || ''}\nWants to become a teacher: ${profile.want_to_teach ? 'Yes' : 'No'}\n`;
    await s3.send(new PutObjectCommand({ Bucket, Key: prefix + 'profile.txt', Body: txt, ContentType: 'text/plain' }));

    // If user indicated they want to become a teacher, record a teacher request
    if (profile.want_to_teach) {
      try {
        const emailNormalized = normalizeEmail(req.session.user.email);
        const displayName = profile.name || req.session.user.name || req.session.user.email;
        if (emailNormalized) {
          // 1) Ensure a pending teacher entry exists in interests.json
          try {
            const list = readInterestsFile();
            const now = new Date().toISOString();
            const hasPending = (list || []).some(it => {
              if (!it || !it.email) return false;
              const sameEmail = normalizeEmail(it.email) === emailNormalized;
              const role = normalizeRole(it.role);
              const status = String(it.status || '').trim().toLowerCase() || 'pending';
              return sameEmail && role === 'teacher' && (status === 'pending' || status === 'requested');
            });
            if (!hasPending) {
              const entry = {
                id: Date.now().toString(36) + Math.floor(Math.random() * 1000),
                name: displayName,
                email: emailNormalized,
                role: 'teacher',
                message: '',
                status: 'pending',
                notified: false,
                ip: req.ip,
                createdAt: now
              };
              list.push(entry);
              writeInterestsFile(list);
            }
          } catch (e) {
            console.warn('profile teacher-request interests update failed:', e && e.message);
          }

          // 2) Mark permissions role as 'requested' (unless already teacher)
          try {
            const permissions = readUserPermissions();
            const idx = permissions.findIndex(p => normalizeEmail(p.email) === emailNormalized);
            if (idx === -1) {
              permissions.push({ email: req.session.user.email, role: 'requested', notes: '' });
            } else {
              const existingRole = normalizeRole(permissions[idx].role);
              permissions[idx].role = existingRole === 'teacher' ? 'teacher' : 'requested';
            }
            const permFile = path.join(DATA_DIR, 'user_permissions.csv');
            const header = 'email,role,notes\n';
            const rows = permissions.map(p => `${p.email},${p.role},${(p.notes || '').replace(/,/g,';')}`).join('\n');
            fs.writeFileSync(permFile, header + rows, 'utf8');
          } catch (e) {
            console.warn('profile teacher-request permissions update failed:', e && e.message);
          }

          // 3) Mark users.csv requested flag so admin UI shows the request
          try {
            const users = readUsersCSV();
            const lower = emailNormalized;
            const uidx = users.findIndex(u => normalizeEmail(u.email) === lower);
            const now = new Date().toISOString();
            if (uidx === -1) {
              users.push({
                name: displayName,
                email: req.session.user.email,
                first_login: now,
                last_login: now,
                login_count: 0,
                requested: true
              });
            } else {
              users[uidx].requested = true;
            }
            writeUsersCSV(users);
          } catch (e) {
            console.warn('profile teacher-request users.csv update failed:', e && e.message);
          }
        }
      } catch (e) {
        console.warn('profile teacher-request overall update failed:', e && e.message);
      }
    }

    // Mark session as completed
    req.session.needsProfile = false;
    req.session.save && req.session.save(()=>{});

    return res.json({ ok: true, profile });
  } catch (err) {
    console.error('/user/profile save error', err && err.message);
    return res.status(500).json({ ok: false, error: 'save_failed' });
  }
});

// List videos in configured S3 bucket and return presigned URLs.
// Supports optional "subfolder" handling via S3 key prefix:
//   - Global default prefix from env: S3_VIDEOS_PREFIX (e.g., "reels/")
//   - Request-specific override: /s3/videos?prefix=user-folder/
app.get('/s3/videos', async (req, res) => {
  if (!process.env.S3_BUCKET_NAME || !process.env.AWS_REGION) {
    return res.status(500).json({ error: 's3_not_configured' });
  }
  try {
    const Bucket = process.env.S3_BUCKET_NAME;

    // Determine which prefix ("subfolder") to list under, if any.
    // If S3_VIDEOS_PREFIX is set, it acts as the default root; a
    // request query ?prefix=... can override or further narrow it.
    const envPrefix = (process.env.S3_VIDEOS_PREFIX || '').trim();
    let reqPrefix = (req.query && req.query.prefix ? String(req.query.prefix) : '').trim();

    // Normalize prefixes: remove leading slashes so that S3 treats
    // them as key prefixes rather than absolute paths.
    const normalizePrefix = (p) => p.replace(/^\/+/, '');

    let finalPrefix = '';
    if (envPrefix && reqPrefix) {
      finalPrefix = normalizePrefix(envPrefix.replace(/\/+$/, '') + '/' + reqPrefix);
    } else if (reqPrefix) {
      finalPrefix = normalizePrefix(reqPrefix);
    } else if (envPrefix) {
      finalPrefix = normalizePrefix(envPrefix);
    }

    const params = { Bucket, MaxKeys: 1000 };
    if (finalPrefix) {
      params.Prefix = finalPrefix;
    }

    const data = await s3.send(new ListObjectsV2Command(params));
    // Only include common video file extensions. This avoids returning
    // non-video objects like profile.json or profile.txt which the
    // frontend previously treated as videos.
    const videoExtRegex = /\.(mp4|webm|mov|m4v|mkv|ogg|ogv|avi|3gp|mpeg|mpg)$/i;
    const allFiles = (data.Contents || []).filter((obj) => obj && typeof obj.Key === 'string' && !obj.Key.endsWith('/'));
    const rawFiles = allFiles.filter(f => videoExtRegex.test(f.Key));
    if (rawFiles.length !== allFiles.length) {
      console.log(`/s3/videos - Bucket=${Bucket} prefix=${finalPrefix || ''} total=${allFiles.length} videos=${rawFiles.length} (non-video files skipped)`);
    } else {
      console.log(`/s3/videos - Bucket=${Bucket} prefix=${finalPrefix || ''} count=${rawFiles.length}`);
    }
    const files = await Promise.all(rawFiles.map(async (obj) => {
      const Key = obj.Key;
      // generate a short-lived presigned URL (1 hour)
      let url = null;
      try {
        const signed = await generatePresignedDownloadUrl(Key, { expiresInSeconds: 3600 });
        url = signed && signed.url ? signed.url : null;
      } catch (e) {
        console.warn('Failed to presign S3 key', Key, e && e.message);
      }
      // public location (works when objects are public-read)
      const location = `https://${Bucket}.s3.amazonaws.com/${encodeURI(Key)}`;
      console.log('S3 object:', { Key, url: url ? url.substring(0, 120) + (url.length > 120 ? '...' : '') : null, location: location.substring(0,120), size: obj.Size });
      return { key: Key, url, location, lastModified: obj.LastModified, size: obj.Size };
    }));
    return res.json({ files, prefix: finalPrefix || null });
  } catch (err) {
    console.error('S3 list error', err && err.message);
    return res.status(500).json({ error: 'list_failed' });
  }
});

// Return a presigned URL for a specific S3 key. Clients can call this when
// the /s3/videos response includes only keys (not full presigned URLs).
app.get('/s3/presign', async (req, res) => {
  try {
    if (!process.env.AWS_S3_BUCKET || !process.env.AWS_REGION) {
      return res.status(500).json({ error: 's3_not_configured' });
    }
    const key = req.query && req.query.key ? String(req.query.key) : null;
    if (!key) return res.status(400).json({ error: 'missing_key' });
    const result = await generatePresignedDownloadUrl(String(key), { expiresInSeconds: 3600 });
    return res.json({ ok: true, url: result.url, key: result.key, bucket: result.bucket, status: result.status });
  } catch (err) {
    console.error('Presign error', err && err.message);
    const status = err instanceof S3UploadError ? err.statusCode : 500;
    const errorCode = err instanceof S3UploadError ? err.code : 'presign_failed';
    return res.status(status).json({ ok: false, error: errorCode, message: err && err.message });
  }
});

// Return a presigned upload URL for direct-to-S3 uploads.
app.get('/s3/presign-upload', async (req, res) => {
  try {
    if (!process.env.AWS_S3_BUCKET || !process.env.AWS_REGION) {
      return res.status(500).json({ error: 's3_not_configured' });
    }
    const key = req.query && req.query.key ? String(req.query.key) : null;
    const contentType = req.query && req.query.contentType ? String(req.query.contentType) : 'application/octet-stream';
    if (!key) return res.status(400).json({ error: 'missing_key' });

    const result = await generatePresignedUploadUrl(key, {
      contentType,
      expiresInSeconds: 900,
    });
    return res.json({ ok: true, url: result.url, key: result.key, bucket: result.bucket, status: result.status });
  } catch (err) {
    const status = err instanceof S3UploadError ? err.statusCode : 500;
    const errorCode = err instanceof S3UploadError ? err.code : 'presign_upload_failed';
    return res.status(status).json({ ok: false, error: errorCode, message: err && err.message });
  }
});

// Explicit download presign endpoint.
app.get('/s3/presign-download', async (req, res) => {
  try {
    if (!process.env.AWS_S3_BUCKET || !process.env.AWS_REGION) {
      return res.status(500).json({ error: 's3_not_configured' });
    }
    const key = req.query && req.query.key ? String(req.query.key) : null;
    if (!key) return res.status(400).json({ error: 'missing_key' });

    const result = await generatePresignedDownloadUrl(key, { expiresInSeconds: 3600 });
    return res.json({ ok: true, url: result.url, key: result.key, bucket: result.bucket, status: result.status });
  } catch (err) {
    const status = err instanceof S3UploadError ? err.statusCode : 500;
    const errorCode = err instanceof S3UploadError ? err.code : 'presign_download_failed';
    return res.status(status).json({ ok: false, error: errorCode, message: err && err.message });
  }
});

// Debug route: return headObject metadata for keys in a prefix (useful to inspect content-type/size)
app.get('/s3/debug', async (req, res) => {
  try {
    if (!process.env.S3_BUCKET_NAME || !process.env.AWS_REGION) return res.status(500).json({ error: 's3_not_configured' });
    const Bucket = process.env.S3_BUCKET_NAME;
    const prefix = (req.query && req.query.prefix) ? String(req.query.prefix).replace(/^\/+/, '') : (process.env.S3_VIDEOS_PREFIX || '').replace(/^\/+/, '');
    const params = { Bucket, MaxKeys: 1000 };
    if (prefix) params.Prefix = prefix;
    const data = await s3.send(new ListObjectsV2Command(params));
    const keys = (data.Contents || []).filter(o => o && o.Key && !o.Key.endsWith('/')).map(o => o.Key);
    const out = [];
    for (const k of keys) {
      try {
        const head = await s3.send(new HeadObjectCommand({ Bucket, Key: k }));
        out.push({ key: k, contentType: head.ContentType, contentLength: head.ContentLength });
      } catch (e) {
        out.push({ key: k, error: e && e.code });
      }
    }
    return res.json({ prefix: prefix || null, count: out.length, files: out });
  } catch (e) {
    console.error('/s3/debug error', e && e.message);
    return res.status(500).json({ error: 'debug_failed' });
  }
});

// List recent videos stored in Drive.
app.get("/videos", ensureAuthed, async (req, res) => {
  try {
    const drive = getDriveForRequest(req);
    if (!drive) {
      return res.status(401).json({ error: "not_authenticated" });
    }
    
    // Get or create folder ID
    let folderId = req.session.appFolderId;
    if (!folderId) {
      folderId = await getOrCreateAppFolder(drive);
      if (folderId) {
        req.session.appFolderId = folderId;
      }
    }
    
    const folderQuery = folderId
      ? `'${folderId}' in parents and `
      : "";
    const response = await drive.files.list({
      q: `${folderQuery}mimeType contains 'video/' and trashed = false`,
      // Request mimeType so we can defensively filter out non-video items
      fields: "files(id,name,createdTime,mimeType)",
      orderBy: "createdTime desc",
      pageSize: 50,
    });

    const allFiles = response.data.files || [];
    const videoFiles = allFiles.filter(f => f && f.mimeType && String(f.mimeType).toLowerCase().startsWith('video/'));
    if (videoFiles.length !== allFiles.length) {
      console.log(`/videos: filtered out ${allFiles.length - videoFiles.length} non-video items for session user`);
    }

    res.json({ files: videoFiles });
  } catch (error) {
    console.error(error);
    if (isInsufficientScopeError(error)) {
      clearStoredTokens(req);
      return res.status(401).json({ error: 'insufficient_scope', action: '/auth/google' });
    }
    res.status(500).json({ error: "list_failed" });
  }
});

// Stream a Drive video file to the browser.
app.get("/stream/:id", ensureAuthed, async (req, res) => {
  try {
    const fileId = req.params.id;
    const drive = getDriveForRequest(req);
    if (!drive) {
      return res.status(401).json({ error: "not_authenticated" });
    }
    // Fetch file metadata first so we can set proper headers for the client
    let meta = null;
    try {
      const md = await drive.files.get({ fileId, fields: 'id,name,mimeType,size' });
      meta = md && md.data ? md.data : null;
    } catch (merr) {
      console.warn('/stream: failed to fetch metadata for', fileId, merr && merr.message);
    }

    try {
      if (meta && meta.mimeType) res.setHeader('Content-Type', meta.mimeType);
      if (meta && meta.size) {
        res.setHeader('Content-Length', String(meta.size));
        res.setHeader('Accept-Ranges', 'bytes');
      }

      // If client requested a Range, pass it through to Drive so partial content can be served
      const opts = { responseType: 'stream' };
      if (req.headers.range) {
        opts.headers = { Range: req.headers.range };
      }

      const driveRes = await drive.files.get({ fileId, alt: 'media' }, opts);

      // If Drive returned a status (e.g., 206 for range) forward it
      try {
        if (driveRes && driveRes.status) {
          res.status(driveRes.status);
        }
      } catch (sErr) {}

      // If Drive returned headers (e.g., content-range), forward them
      try {
        if (driveRes && driveRes.headers) {
          Object.keys(driveRes.headers).forEach(h => {
            // Don't overwrite transfer-encoding
            if (!['transfer-encoding'].includes(h.toLowerCase())) {
              res.setHeader(h, driveRes.headers[h]);
            }
          });
        }
      } catch (fh) {}

      driveRes.data
        .on('error', (error) => {
          console.error('/stream pipe error', error && (error.message || error));
          try { res.sendStatus(500); } catch (_) {}
        })
        .pipe(res);
    } catch (err) {
      console.error('/stream error fetching media', err && (err.message || err));
      if (isInsufficientScopeError(err)) {
        clearStoredTokens(req);
        return res.status(401).json({ error: 'insufficient_scope', action: '/auth/google' });
      }
      return res.status(500).json({ error: 'stream_failed' });
    }
  } catch (error) {
    console.error(error);
    if (isInsufficientScopeError(error)) {
      clearStoredTokens(req);
      return res.status(401).json({ error: 'insufficient_scope', action: '/auth/google' });
    }
    res.status(500).json({ error: "stream_failed" });
  }
});

// Diagnostic: drive status for current session (does NOT leak secrets)
app.get('/drive/status', (req, res) => {
  try {
    const tokenFileExists = fs.existsSync(TOKEN_PATH);
    let tokenSummary = null;
    try {
      if (tokenFileExists) {
        const raw = fs.readFileSync(TOKEN_PATH, 'utf8');
        const parsed = JSON.parse(raw || '{}');
        tokenSummary = {
          hasAccessToken: !!parsed.access_token,
          hasRefreshToken: !!parsed.refresh_token,
          expiry_date: parsed.expiry_date || null
        };
      }
    } catch (e) {
      tokenSummary = { error: 'failed_to_read_token_file' };
    }

    const sessionHasTokens = Boolean(req.session && req.session.tokens && (req.session.tokens.access_token || req.session.tokens.refresh_token));
    const sessionUser = req.session && req.session.user ? { email: req.session.user.email, name: req.session.user.name } : null;

    return res.json({
      driveConfigured: DRIVE_CONFIGURED,
      tokenFileExists,
      tokenSummary,
      sessionHasTokens,
      sessionUser,
      s3Configured: !!(process.env.S3_BUCKET_NAME && process.env.AWS_REGION),
      hostname: process.env.HOSTNAME || null,
    });
  } catch (e) {
    console.error('/drive/status error', e && e.message);
    return res.status(500).json({ error: 'status_failed' });
  }
});

const PROTOCOL = process.env.FORCE_SECURE === 'true' ? 'https' : 'http';
const resolveHostForLog = () => {
  const raw = String(process.env.HOSTNAME || process.env.APP_URL || 'simtkus.com').trim();
  if (!raw) return null;
  return raw.replace(/^https?:\/\//, '').replace(/\/$/, '');
};
const hostForLog = resolveHostForLog();
const hostLog = hostForLog ? `${PROTOCOL}://${hostForLog}` : null;
const listeners = LISTEN_PORTS.length ? LISTEN_PORTS : [PORT];

// Initialize UPnP client for automatic port forwarding
const upnpClient = upnp.createClient();

listeners.forEach(port => {
  app.listen(port, '0.0.0.0', () => {
    const protocolForPort = (port === 80 || port === 443) ? 'https' : PROTOCOL;
    const url = hostForLog ? `${protocolForPort}://${hostForLog}` : `http://localhost:${port}`;
    console.log(`Server listening on port ${port}; access the site at ${url}`);

    // Setup UPnP port mapping asynchronously with timeout (non-blocking)
    (async () => {
      try {
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('UPnP timeout after 5s')), 5000)
        );

        const mappingPromise = upnpClient.portMapping({
          public: port,
          private: port,
          protocol: 'tcp',
          ttl: 0 // permanent mapping
        });

        await Promise.race([mappingPromise, timeoutPromise]);
        console.log(`✓ UPnP: Port ${port} successfully mapped on router`);
      } catch (err) {
        console.log(`⚠ UPnP: Could not map port ${port} (router may not support UPnP or timeout): ${err.message}`);
      }
    })();

    // Attempt DNS sync on startup when configured (run once on first listener)
    if (port === listeners[0]) {
      (async () => {
        try {
          if (AUTO_ALIDNS) {
            const res = await ensureAlidnsARecord();
            if (res && res.ok) console.log('ALIDNS sync result:', res);
            else console.log('ALIDNS sync skipped or failed:', res && res.reason);
          } else if (AUTO_ROUTE53) {
            const res = await ensureRoute53ARecord();
            if (res && res.ok) console.log('Route53 sync result:', res);
            else console.log('Route53 sync skipped or failed:', res && res.reason);
          }
        } catch (e) {
          console.error('DNS sync error', e && e.message);
        }
      })();
    }
  });
});
