import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = path.resolve(__dirname, '..', 'relay_data.sqlite');

export type JobStatus = 'PENDING' | 'DISPATCHED' | 'FAILED' | 'CANCELLED';
export type JobType = 'TEXT' | 'MEDIA' | 'POLL';
export type LogStatus = 'SUCCESS' | 'FAILED' | 'BLOCKED';

export interface ScheduledJob {
  id: string;
  execute_at: string;
  type: JobType;
  payload: string;
  status: JobStatus;
  created_at: string;
}

export interface DispatchLog {
  id: string;
  timestamp: string;
  type: string;
  summary: string;
  status: LogStatus;
  destinations: string;
}

export interface BroadcastPayload {
  text?: string;
  filePath?: string;
  originalName?: string;
  mimeType?: string;
  sendAsVoice?: boolean;
  pinDuration?: number;
  pollQuestion?: string;
  pollOptions?: string[];
  allowMultipleAnswers?: boolean;
}

/** WhatsApp pin durations (seconds): 24h, 7d, 30d */
export const PIN_ALLOWED = [86400, 604800, 2592000] as const;

export function clampPinDuration(seconds: number): number | undefined {
  if (!seconds || seconds <= 0) return undefined;
  // Map to nearest allowed value without exceeding 30 days
  let best: number = PIN_ALLOWED[0];
  let bestDiff = Math.abs(seconds - best);
  for (const v of PIN_ALLOWED) {
    const d = Math.abs(seconds - v);
    if (d < bestDiff) {
      best = v;
      bestDiff = d;
    }
  }
  return best;
}

let db: Database.Database;

export function initDb(): Database.Database {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS scheduled_jobs (
      id TEXT PRIMARY KEY,
      execute_at TEXT NOT NULL,
      type TEXT NOT NULL,
      payload TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_jobs_status_execute
      ON scheduled_jobs (status, execute_at);

    CREATE TABLE IF NOT EXISTS dispatch_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      type TEXT NOT NULL,
      summary TEXT NOT NULL,
      status TEXT NOT NULL,
      destinations TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS message_digests (
      digest TEXT PRIMARY KEY,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expired INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions (expired);
  `);

  // Purge digests older than 24h on startup
  db.prepare(
    `DELETE FROM message_digests WHERE created_at < datetime('now', '-1 day')`
  ).run();

  return db;
}

export function getDb(): Database.Database {
  if (!db) {
    throw new Error('Database not initialized. Call initDb() first.');
  }
  return db;
}

export function closeDb(): void {
  if (db) {
    db.close();
  }
}

export function insertJob(
  id: string,
  executeAt: string,
  type: JobType,
  payload: BroadcastPayload
): void {
  const stmt = getDb().prepare(`
    INSERT INTO scheduled_jobs (id, execute_at, type, payload, status, created_at)
    VALUES (?, ?, ?, ?, 'PENDING', ?)
  `);
  stmt.run(id, executeAt, type, JSON.stringify(payload), new Date().toISOString());
}

export function getPendingJobs(): ScheduledJob[] {
  const stmt = getDb().prepare(`
    SELECT * FROM scheduled_jobs
    WHERE status = 'PENDING' AND execute_at <= datetime('now')
    ORDER BY execute_at ASC
  `);
  return stmt.all() as ScheduledJob[];
}

export function updateJobStatus(id: string, status: JobStatus): void {
  const stmt = getDb().prepare(`
    UPDATE scheduled_jobs SET status = ? WHERE id = ?
  `);
  stmt.run(status, id);
}

export function getJobById(id: string): ScheduledJob | undefined {
  const stmt = getDb().prepare(`SELECT * FROM scheduled_jobs WHERE id = ?`);
  return stmt.get(id) as ScheduledJob | undefined;
}

export function getRecentJobs(limit = 50): ScheduledJob[] {
  const stmt = getDb().prepare(`
    SELECT * FROM scheduled_jobs
    ORDER BY created_at DESC
    LIMIT ?
  `);
  return stmt.all(limit) as ScheduledJob[];
}

export function insertDispatchLog(
  id: string,
  type: string,
  summary: string,
  status: LogStatus,
  destinations: string[]
): void {
  const stmt = getDb().prepare(`
    INSERT INTO dispatch_logs (id, timestamp, type, summary, status, destinations)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(id, new Date().toISOString(), type, summary, status, JSON.stringify(destinations));
}

export function getRecentLogs(limit = 50): DispatchLog[] {
  const stmt = getDb().prepare(`
    SELECT * FROM dispatch_logs
    ORDER BY timestamp DESC
    LIMIT ?
  `);
  return stmt.all(limit) as DispatchLog[];
}

/** Returns true if digest is new (and records it). False if duplicate within 24h. */
export function tryRecordDigest(digest: string): boolean {
  const existing = getDb()
    .prepare(
      `SELECT 1 FROM message_digests WHERE digest = ? AND created_at >= datetime('now', '-1 day')`
    )
    .get(digest);
  if (existing) return false;
  getDb()
    .prepare(
      `INSERT OR REPLACE INTO message_digests (digest, created_at) VALUES (?, ?)`
    )
    .run(digest, new Date().toISOString());
  return true;
}

export function jobPayloadSummary(job: ScheduledJob): string {
  try {
    const p = JSON.parse(job.payload) as BroadcastPayload;
    if (job.type === 'POLL') return p.pollQuestion ?? 'Poll';
    if (job.type === 'MEDIA') return p.originalName ?? 'media';
    const t = p.text ?? '';
    return t.length > 60 ? t.slice(0, 57) + '...' : t;
  } catch {
    return '(payload)';
  }
}

// ---- Minimal SQLite session store for express-session ----
export class SqliteSessionStore extends session.Store {
  get(sid: string, cb: (err: any, session?: session.SessionData | null) => void): void {
    try {
      const row = getDb()
        .prepare(`SELECT sess, expired FROM sessions WHERE sid = ?`)
        .get(sid) as { sess: string; expired: number } | undefined;
      if (!row || row.expired < Date.now()) {
        if (row) {
          getDb().prepare(`DELETE FROM sessions WHERE sid = ?`).run(sid);
        }
        cb(null, null);
        return;
      }
      cb(null, JSON.parse(row.sess));
    } catch (err) {
      cb(err as Error);
    }
  }

  set(sid: string, sess: session.SessionData, cb: (err?: any) => void): void {
    try {
      const maxAge = (sess.cookie?.maxAge as number) || 24 * 60 * 60 * 1000;
      const expired = Date.now() + maxAge;
      getDb()
        .prepare(
          `INSERT OR REPLACE INTO sessions (sid, sess, expired) VALUES (?, ?, ?)`
        )
        .run(sid, JSON.stringify(sess), expired);
      cb();
    } catch (err) {
      cb(err as Error);
    }
  }

  destroy(sid: string, cb: (err?: any) => void): void {
    try {
      getDb().prepare(`DELETE FROM sessions WHERE sid = ?`).run(sid);
      cb();
    } catch (err) {
      cb(err as Error);
    }
  }

  touch(sid: string, sess: session.SessionData, cb: (err?: any) => void): void {
    this.set(sid, sess, cb);
  }
}
