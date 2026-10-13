import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import http from 'http';

import {
  initDb,
  closeDb,
  insertJob,
  getRecentJobs,
  getRecentLogs,
  insertDispatchLog,
  BroadcastPayload,
  clampPinDuration,
  jobPayloadSummary,
  SqliteSessionStore,
} from './db.js';
import { AnnouncementBot } from './bot.js';
import { startScheduler, stopScheduler, cancelJob, isSchedulerBusy } from './scheduler.js';
import { log } from './logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.PORT || '3000', 10);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const GROUP_A_ID = process.env.GROUP_A_ID || '';
const GROUP_B_ID = process.env.GROUP_B_ID || '';
const TRUST_PROXY = process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true';
const FORCE_SECURE_COOKIE = process.env.SECURE_COOKIE === '1' || process.env.SECURE_COOKIE === 'true';

if (!ADMIN_PASSWORD) {
  log.error('FATAL: ADMIN_PASSWORD must be set in .env');
  process.exit(1);
}

const UPLOADS_DIR = path.resolve(__dirname, '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const startedAt = Date.now();

// ---- Database & Bot ----
initDb();
const bot = new AnnouncementBot(GROUP_A_ID, GROUP_B_ID);

// ---- Express ----
const app = express();
if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        formAction: ["'self'"],
      },
    },
  })
);

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const sessionStore = new SqliteSessionStore();

app.use(
  session({
    store: sessionStore,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax',
      // Set SECURE_COOKIE=true behind HTTPS tunnel
      secure: FORCE_SECURE_COOKIE,
    },
  })
);

// Multer (compatible with 1.x and 2.x)
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const unique = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, unique);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 64 * 1024 * 1024 },
});

// ---- Auth / CSRF helpers ----
declare module 'express-session' {
  interface SessionData {
    authenticated?: boolean;
    csrfToken?: string;
  }
}

function timingSafePasswordCompare(input: string, expected: string): boolean {
  const a = Buffer.from(input);
  const b = Buffer.from(expected);
  const maxLen = Math.max(a.length, b.length, 1);
  const paddedA = Buffer.alloc(maxLen);
  const paddedB = Buffer.alloc(maxLen);
  a.copy(paddedA);
  b.copy(paddedB);
  const equal = crypto.timingSafeEqual(paddedA, paddedB);
  return equal && a.length === b.length;
}

function ensureCsrf(req: Request): string {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  }
  return req.session.csrfToken;
}

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (req.session?.authenticated) {
    next();
    return;
  }
  res.redirect(302, '/login');
}

function requireCsrf(req: Request, res: Response, next: NextFunction): void {
  const token = (req.body?._csrf as string) || (req.headers['x-csrf-token'] as string) || '';
  const expected = req.session?.csrfToken || '';
  if (!expected || !token || token.length !== expected.length) {
    res.status(403).send('Invalid CSRF token');
    return;
  }
  const a = Buffer.from(token);
  const b = Buffer.from(expected);
  if (!crypto.timingSafeEqual(a, b)) {
    res.status(403).send('Invalid CSRF token');
    return;
  }
  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Try again in 15 minutes.',
});

// ---- Routes ----

app.get('/health', (_req: Request, res: Response) => {
  res.json({
    ok: true,
    ready: bot.isReady(),
    groupsConfigured: bot.areGroupsConfigured(),
    groupsValid: bot.areGroupsValid(),
    killSwitch: bot.isKillSwitchActive(),
    uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
  });
});

app.get('/login', (req: Request, res: Response) => {
  if (req.session?.authenticated) {
    res.redirect('/');
    return;
  }
  const csrf = ensureCsrf(req);
  res.send(loginPage(csrf));
});

app.post('/login', loginLimiter, (req: Request, res: Response) => {
  const password = (req.body.password as string) || '';
  const csrf = ensureCsrf(req);
  // CSRF optional on login (rate-limited); still check if present
  const bodyCsrf = (req.body._csrf as string) || '';
  if (bodyCsrf && bodyCsrf !== csrf) {
    res.status(403).send(loginPage(csrf, 'Invalid CSRF token'));
    return;
  }
  if (timingSafePasswordCompare(password, ADMIN_PASSWORD)) {
    req.session.authenticated = true;
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    res.redirect('/');
    return;
  }
  res.status(401).send(loginPage(csrf, 'Invalid password'));
});

app.post('/logout', requireAuth, requireCsrf, (req: Request, res: Response) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

app.get('/', requireAuth, (req: Request, res: Response) => {
  const csrf = ensureCsrf(req);
  const jobs = getRecentJobs(30);
  const logs = getRecentLogs(30);
  res.send(
    dashboardPage({
      csrf,
      botReady: bot.isReady(),
      killSwitch: bot.isKillSwitchActive(),
      groupsConfigured: bot.areGroupsConfigured(),
      groupsValid: bot.areGroupsValid(),
      groupLabels: bot.getGroupLabels(),
      jobs,
      logs,
    })
  );
});

app.post(
  '/api/broadcast',
  requireAuth,
  requireCsrf,
  upload.single('file'),
  async (req: Request, res: Response) => {
    try {
      if (!bot.areGroupsConfigured()) {
        res.redirect('/?msg=no_groups');
        return;
      }

      const text = (req.body.text as string) || '';
      const scheduleAt = (req.body.schedule_at as string) || '';
      let pinDuration = parseInt(req.body.pin_duration || '0', 10) || 0;
      pinDuration = clampPinDuration(pinDuration) ?? 0;
      const sendAsVoice = req.body.send_as_voice === 'on' || req.body.send_as_voice === 'true';
      const immediate = !scheduleAt;

      const file = req.file;
      let type: 'TEXT' | 'MEDIA' = 'TEXT';
      const payload: BroadcastPayload = {
        text: text || undefined,
        pinDuration: pinDuration > 0 ? pinDuration : undefined,
      };

      if (file) {
        type = 'MEDIA';
        payload.filePath = file.path;
        payload.originalName = file.originalname;
        payload.mimeType = file.mimetype;
        payload.sendAsVoice = sendAsVoice;
      }

      if (!payload.text && !payload.filePath) {
        res.status(400).send('Either text or file is required');
        return;
      }

      // Queue if not ready or kill switch, or explicit schedule
      const shouldQueue =
        !immediate ||
        bot.isKillSwitchActive() ||
        !bot.isReady();

      if (shouldQueue && immediate) {
        // Auto-queue near-term so cron picks it up
        const executeAt = new Date().toISOString();
        const id = uuidv4();
        insertJob(id, executeAt, type, payload);
        if (bot.isKillSwitchActive()) {
          insertDispatchLog(
            uuidv4(),
            type === 'TEXT' ? 'Text' : 'Media',
            payload.text?.slice(0, 80) || payload.originalName || 'media',
            'BLOCKED',
            [GROUP_A_ID, GROUP_B_ID]
          );
          res.redirect('/?msg=queued_blocked');
          return;
        }
        res.redirect('/?msg=queued');
        return;
      }

      if (!immediate) {
        // datetime-local is local time without TZ; interpret as local and convert to UTC ISO
        const executeAt = localDatetimeToUtcIso(scheduleAt);
        insertJob(uuidv4(), executeAt, type, payload);
        res.redirect('/?msg=scheduled');
        return;
      }

      // Immediate send path
      const result = await bot.broadcast(type, payload);
      if (result.success) {
        insertDispatchLog(
          uuidv4(),
          type === 'TEXT' ? 'Text' : 'Media',
          payload.text?.slice(0, 80) || payload.originalName || 'media',
          'SUCCESS',
          [GROUP_A_ID, GROUP_B_ID]
        );
      } else {
        insertDispatchLog(
          uuidv4(),
          type === 'TEXT' ? 'Text' : 'Media',
          (payload.text?.slice(0, 80) || payload.originalName || 'media') +
            (result.error ? ` | ${result.error}` : ''),
          result.blocked ? 'BLOCKED' : 'FAILED',
          [GROUP_A_ID, GROUP_B_ID]
        );
      }
      if (payload.filePath && fs.existsSync(payload.filePath)) {
        try {
          fs.unlinkSync(payload.filePath);
        } catch {
          /* ignore */
        }
      }
      res.redirect(result.success ? '/?msg=sent' : '/?msg=failed');
    } catch (err) {
      log.error('Broadcast error', err instanceof Error ? err.message : String(err));
      res.status(500).send('Internal error');
    }
  }
);

app.post('/api/poll', requireAuth, requireCsrf, async (req: Request, res: Response) => {
  try {
    if (!bot.areGroupsConfigured()) {
      res.redirect('/?msg=no_groups');
      return;
    }

    const question = (req.body.question as string) || '';
    const optionsRaw = (req.body.options as string) || '';
    const allowMultiple = req.body.allow_multiple === 'on' || req.body.allow_multiple === 'true';
    const scheduleAt = (req.body.schedule_at as string) || '';
    let pinDuration = parseInt(req.body.pin_duration || '0', 10) || 0;
    pinDuration = clampPinDuration(pinDuration) ?? 0;

    const options = optionsRaw
      .split('\n')
      .map((o) => o.trim())
      .filter(Boolean);

    if (!question || options.length < 2) {
      res.status(400).send('Poll requires a question and at least 2 options');
      return;
    }

    const payload: BroadcastPayload = {
      pollQuestion: question,
      pollOptions: options,
      allowMultipleAnswers: allowMultiple,
      pinDuration: pinDuration > 0 ? pinDuration : undefined,
    };

    const immediate = !scheduleAt;
    const shouldQueue = !immediate || bot.isKillSwitchActive() || !bot.isReady();

    if (shouldQueue && immediate) {
      insertJob(uuidv4(), new Date().toISOString(), 'POLL', payload);
      res.redirect(bot.isKillSwitchActive() ? '/?msg=queued_blocked' : '/?msg=queued');
      return;
    }

    if (!immediate) {
      insertJob(uuidv4(), localDatetimeToUtcIso(scheduleAt), 'POLL', payload);
      res.redirect('/?msg=scheduled');
      return;
    }

    const result = await bot.broadcast('POLL', payload);
    insertDispatchLog(
      uuidv4(),
      'Poll',
      question + (result.error ? ` | ${result.error}` : ''),
      result.success ? 'SUCCESS' : result.blocked ? 'BLOCKED' : 'FAILED',
      [GROUP_A_ID, GROUP_B_ID]
    );
    res.redirect(result.success ? '/?msg=sent' : '/?msg=failed');
  } catch (err) {
    log.error('Poll error', err instanceof Error ? err.message : String(err));
    res.status(500).send('Internal error');
  }
});

app.post('/api/cancel-job', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const jobId = (req.body.job_id as string) || '';
  if (!jobId) {
    res.status(400).send('job_id required');
    return;
  }
  const ok = cancelJob(jobId);
  res.redirect(ok ? '/?msg=cancelled' : '/?msg=cancel_failed');
});

app.post('/api/toggle-switch', requireAuth, requireCsrf, (req: Request, res: Response) => {
  bot.setKillSwitch(!bot.isKillSwitchActive());
  res.redirect('/');
});

// ---- Helpers ----

/** Parse datetime-local value (no timezone) as local time → UTC ISO */
function localDatetimeToUtcIso(localValue: string): string {
  // localValue like "2026-10-02T15:30"
  const d = new Date(localValue);
  if (Number.isNaN(d.getTime())) {
    return new Date().toISOString();
  }
  return d.toISOString();
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function csrfField(token: string): string {
  return `<input type="hidden" name="_csrf" value="${escapeHtml(token)}" />`;
}

// ---- HTML ----

function loginPage(csrf: string, error?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WA Announcer – Login</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0f1419;
      color: #e7e9ea;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      background: #1a2332;
      padding: 2rem;
      border-radius: 12px;
      width: 100%;
      max-width: 380px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    h1 { margin: 0 0 0.5rem; font-size: 1.4rem; }
    p.sub { color: #8b98a5; margin: 0 0 1.5rem; font-size: 0.9rem; }
    label { display: block; margin-bottom: 0.4rem; font-size: 0.85rem; color: #8b98a5; }
    input[type=password] {
      width: 100%;
      padding: 0.75rem 1rem;
      border: 1px solid #38444d;
      border-radius: 8px;
      background: #0f1419;
      color: #e7e9ea;
      font-size: 1rem;
      margin-bottom: 1rem;
    }
    input:focus { outline: none; border-color: #1d9bf0; }
    button {
      width: 100%;
      padding: 0.75rem;
      background: #1d9bf0;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { background: #1a8cd8; }
    .error { background: #3d1f1f; color: #f4212e; padding: 0.6rem 1rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>WA Announcer</h1>
    <p class="sub">Admin authentication required</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    <form method="POST" action="/login">
      ${csrfField(csrf)}
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autofocus autocomplete="current-password" />
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`;
}

interface DashOpts {
  csrf: string;
  botReady: boolean;
  killSwitch: boolean;
  groupsConfigured: boolean;
  groupsValid: boolean | null;
  groupLabels: { a: string; b: string };
  jobs: ReturnType<typeof getRecentJobs>;
  logs: ReturnType<typeof getRecentLogs>;
}

function dashboardPage(o: DashOpts): string {
  const msgMap: Record<string, string> = {
    sent: 'Broadcast sent successfully.',
    scheduled: 'Job scheduled.',
    queued: 'Queued — will send when WhatsApp is ready.',
    queued_blocked: 'Queued but blocked by emergency pause (will send after resume).',
    failed: 'Broadcast failed. Check logs.',
    blocked: 'Broadcast blocked by emergency pause.',
    cancelled: 'Job cancelled.',
    cancel_failed: 'Could not cancel job (already processed or missing).',
    no_groups: 'GROUP_A_ID / GROUP_B_ID not configured in .env.',
  };

  const groupBadge =
    !o.groupsConfigured
      ? '<span class="badge err">Groups not configured</span>'
      : o.groupsValid === false
        ? '<span class="badge warn">Group IDs not found</span>'
        : o.groupsValid === true
          ? '<span class="badge ok">Groups OK</span>'
          : '<span class="badge off">Groups unchecked</span>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WA Announcer – Dashboard</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0f1419;
      color: #e7e9ea;
      margin: 0;
      padding: 0 0 3rem;
    }
    header {
      background: #1a2332;
      padding: 1rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid #38444d;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    header h1 { margin: 0; font-size: 1.2rem; }
    .status {
      display: flex;
      gap: 0.6rem;
      align-items: center;
      font-size: 0.85rem;
      flex-wrap: wrap;
    }
    .badge {
      padding: 0.25rem 0.6rem;
      border-radius: 999px;
      font-weight: 600;
      font-size: 0.75rem;
    }
    .badge.ok { background: #0a3d2a; color: #00ba7c; }
    .badge.warn { background: #3d2a0a; color: #ffad1f; }
    .badge.err { background: #3d1f1f; color: #f4212e; }
    .badge.off { background: #2a2a2a; color: #8b98a5; }
    main { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
    .flash {
      background: #0a3d2a;
      color: #00ba7c;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      margin-bottom: 1.25rem;
    }
    .hint {
      background: #1a2332;
      border: 1px solid #38444d;
      color: #8b98a5;
      padding: 0.6rem 0.9rem;
      border-radius: 8px;
      margin-bottom: 1rem;
      font-size: 0.85rem;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
    }
    @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
    .card {
      background: #1a2332;
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid #38444d;
    }
    .card h2 { margin: 0 0 1rem; font-size: 1rem; color: #8b98a5; text-transform: uppercase; letter-spacing: 0.04em; }
    label { display: block; margin-bottom: 0.3rem; font-size: 0.8rem; color: #8b98a5; }
    input[type=text], input[type=datetime-local], input[type=number], textarea, input[type=file], select {
      width: 100%;
      padding: 0.6rem 0.75rem;
      border: 1px solid #38444d;
      border-radius: 8px;
      background: #0f1419;
      color: #e7e9ea;
      font-size: 0.95rem;
      margin-bottom: 0.85rem;
    }
    textarea { min-height: 90px; resize: vertical; }
    input:focus, textarea:focus, select:focus { outline: none; border-color: #1d9bf0; }
    .row { display: flex; gap: 0.75rem; flex-wrap: wrap; }
    .row > * { flex: 1; min-width: 120px; }
    .check { display: flex; align-items: center; gap: 0.4rem; margin-bottom: 0.85rem; font-size: 0.9rem; }
    .check input { width: auto; margin: 0; }
    button, .btn {
      padding: 0.6rem 1.1rem;
      background: #1d9bf0;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover, .btn:hover { background: #1a8cd8; }
    button.danger { background: #f4212e; }
    button.danger:hover { background: #d91a26; }
    button.secondary { background: #38444d; }
    button.secondary:hover { background: #4a5568; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    th, td {
      text-align: left;
      padding: 0.5rem 0.4rem;
      border-bottom: 1px solid #2a3544;
      vertical-align: top;
    }
    th { color: #8b98a5; font-weight: 500; }
    .status-PENDING { color: #ffad1f; }
    .status-DISPATCHED, .status-SUCCESS { color: #00ba7c; }
    .status-FAILED, .status-BLOCKED { color: #f4212e; }
    .status-CANCELLED { color: #8b98a5; }
    .actions form { display: inline; }
    .actions button { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
    .full { grid-column: 1 / -1; }
    form.inline { display: inline; }
    .muted { color: #8b98a5; font-size: 0.8rem; }
  </style>
</head>
<body>
  <header>
    <h1>WA Announcer</h1>
    <div class="status">
      <span class="badge ${o.botReady ? 'ok' : 'warn'}">${o.botReady ? 'WhatsApp Ready' : 'WhatsApp Connecting…'}</span>
      ${groupBadge}
      <span class="badge ${o.killSwitch ? 'err' : 'ok'}">${o.killSwitch ? 'EMERGENCY PAUSE ON' : 'Live'}</span>
      <form method="POST" action="/api/toggle-switch" class="inline">
        ${csrfField(o.csrf)}
        <button type="submit" class="${o.killSwitch ? 'secondary' : 'danger'}">${o.killSwitch ? 'Resume' : 'Emergency Pause'}</button>
      </form>
      <form method="POST" action="/logout" class="inline">
        ${csrfField(o.csrf)}
        <button type="submit" class="secondary">Logout</button>
      </form>
    </div>
  </header>
  <main>
    <div id="flash" class="flash" style="display:none"></div>
    <div class="hint">
      Targets: <strong>${escapeHtml(o.groupLabels.a)}</strong> · <strong>${escapeHtml(o.groupLabels.b)}</strong><br/>
      Schedule times use your <em>browser local timezone</em> and are stored as UTC.
      Pin duration maps to WhatsApp-allowed values (24h / 7d / 30d).
    </div>

    <div class="grid">
      <div class="card">
        <h2>Broadcast Text / Media</h2>
        <form method="POST" action="/api/broadcast" enctype="multipart/form-data">
          ${csrfField(o.csrf)}
          <label for="text">Message text / caption</label>
          <textarea id="text" name="text" placeholder="Announcement text…"></textarea>

          <label for="file">Attach file (optional, max 64 MB)</label>
          <input type="file" id="file" name="file" accept="*/*" />

          <div class="check">
            <input type="checkbox" id="send_as_voice" name="send_as_voice" />
            <label for="send_as_voice" style="margin:0">Send audio as green voice note</label>
          </div>

          <div class="row">
            <div>
              <label for="schedule_at">Schedule (empty = send now / queue if offline)</label>
              <input type="datetime-local" id="schedule_at" name="schedule_at" />
            </div>
            <div>
              <label for="pin_duration">Pin duration</label>
              <select id="pin_duration" name="pin_duration">
                <option value="0">No pin</option>
                <option value="86400">24 hours</option>
                <option value="604800">7 days</option>
                <option value="2592000">30 days</option>
              </select>
            </div>
          </div>

          <button type="submit">Send / Schedule</button>
        </form>
      </div>

      <div class="card">
        <h2>Interactive Poll</h2>
        <form method="POST" action="/api/poll">
          ${csrfField(o.csrf)}
          <label for="question">Poll question</label>
          <input type="text" id="question" name="question" required placeholder="What should we do?" />

          <label for="options">Options (one per line, min 2)</label>
          <textarea id="options" name="options" required placeholder="Option A&#10;Option B&#10;Option C"></textarea>

          <div class="check">
            <input type="checkbox" id="allow_multiple" name="allow_multiple" />
            <label for="allow_multiple" style="margin:0">Allow multiple answers</label>
          </div>

          <div class="row">
            <div>
              <label for="poll_schedule">Schedule (empty = send now / queue if offline)</label>
              <input type="datetime-local" id="poll_schedule" name="schedule_at" />
            </div>
            <div>
              <label for="poll_pin">Pin duration</label>
              <select id="poll_pin" name="pin_duration">
                <option value="0">No pin</option>
                <option value="86400">24 hours</option>
                <option value="604800">7 days</option>
                <option value="2592000">30 days</option>
              </select>
            </div>
          </div>

          <button type="submit">Send / Schedule Poll</button>
        </form>
      </div>

      <div class="card full">
        <h2>Scheduled Jobs</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Execute (UTC)</th>
              <th>Type</th>
              <th>Preview</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${
              o.jobs.length === 0
                ? '<tr><td colspan="6" class="muted">No jobs yet</td></tr>'
                : o.jobs
                    .map(
                      (j) => `<tr>
              <td title="${escapeHtml(j.id)}">${escapeHtml(j.id.slice(0, 8))}…</td>
              <td>${escapeHtml(j.execute_at)}</td>
              <td>${escapeHtml(j.type)}</td>
              <td>${escapeHtml(jobPayloadSummary(j))}</td>
              <td class="status-${j.status}">${escapeHtml(j.status)}</td>
              <td class="actions">
                ${
                  j.status === 'PENDING'
                    ? `<form method="POST" action="/api/cancel-job">
                        ${csrfField(o.csrf)}
                        <input type="hidden" name="job_id" value="${escapeHtml(j.id)}" />
                        <button type="submit" class="danger">Cancel</button>
                      </form>`
                    : ''
                }
              </td>
            </tr>`
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>

      <div class="card full">
        <h2>Dispatch Logs</h2>
        <table>
          <thead>
            <tr>
              <th>Time (UTC)</th>
              <th>Type</th>
              <th>Summary</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${
              o.logs.length === 0
                ? '<tr><td colspan="4" class="muted">No logs yet</td></tr>'
                : o.logs
                    .map(
                      (l) => `<tr>
              <td>${escapeHtml(l.timestamp)}</td>
              <td>${escapeHtml(l.type)}</td>
              <td>${escapeHtml(l.summary)}</td>
              <td class="status-${l.status}">${escapeHtml(l.status)}</td>
            </tr>`
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>
    </div>
  </main>
  <script>
    const params = new URLSearchParams(location.search);
    const msg = params.get('msg');
    const map = ${JSON.stringify(msgMap)};
    if (msg && map[msg]) {
      const el = document.getElementById('flash');
      el.textContent = map[msg];
      el.style.display = 'block';
      history.replaceState(null, '', '/');
    }
  </script>
</body>
</html>`;
}

// ---- Boot & graceful shutdown ----

let server: http.Server;

async function main() {
  log.info('Starting WA Announcer…');
  log.info(`Groups configured: A=${GROUP_A_ID || '(not set)'} B=${GROUP_B_ID || '(not set)'}`);
  if (!GROUP_A_ID || !GROUP_B_ID) {
    log.warn('Set GROUP_A_ID and GROUP_B_ID in .env after QR login and group discovery');
  }

  startScheduler(bot);

  bot.start().catch((err) => {
    log.error('Bot failed to start', err instanceof Error ? err.message : String(err));
  });

  server = app.listen(PORT, () => {
    log.info(`HTTP server listening on http://localhost:${PORT}`);
  });
}

async function gracefulShutdown(signal: string) {
  log.info(`Received ${signal}, shutting down…`);
  stopScheduler();

  // Wait briefly if a job is in flight
  const deadline = Date.now() + 15000;
  while (isSchedulerBusy() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 200));
  }

  await new Promise<void>((resolve) => {
    if (server) {
      server.close(() => resolve());
    } else {
      resolve();
    }
  });

  await bot.shutdown();
  closeDb();
  log.info('Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

main().catch((err) => {
  log.error('Fatal startup error', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
