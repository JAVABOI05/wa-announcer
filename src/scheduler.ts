import cron, { ScheduledTask } from 'node-cron';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  getPendingJobs,
  updateJobStatus,
  insertDispatchLog,
  BroadcastPayload,
  getJobById,
} from './db.js';
import { AnnouncementBot } from './bot.js';
import { log } from './logger.js';

let task: ScheduledTask | null = null;
let running = false;
/** Job IDs already logged as BLOCKED under the current kill-switch activation */
const blockedLogged = new Set<string>();

function cleanupFile(filePath?: string): void {
  if (!filePath) return;
  try {
    const resolved = path.resolve(filePath);
    if (resolved.includes(`${path.sep}uploads${path.sep}`) && fs.existsSync(resolved)) {
      fs.unlinkSync(resolved);
      log.info(`Cleaned up file: ${resolved}`);
    }
  } catch (err) {
    log.warn('File cleanup failed', err instanceof Error ? err.message : String(err));
  }
}

function summarize(payload: BroadcastPayload, type: string): string {
  if (type === 'POLL') return payload.pollQuestion ?? 'Poll';
  if (type === 'MEDIA') return payload.originalName ?? path.basename(payload.filePath ?? 'media');
  const text = payload.text ?? '';
  return text.length > 80 ? text.slice(0, 77) + '...' : text;
}

function typeLabel(t: string): string {
  return t === 'TEXT' ? 'Text' : t === 'MEDIA' ? 'Media' : 'Poll';
}

export function startScheduler(bot: AnnouncementBot): void {
  // Clear blocked-log set when kill switch is turned off (polled each tick)
  let wasKill = false;

  task = cron.schedule('* * * * *', async () => {
    if (running) {
      log.debug('Scheduler tick skipped — previous run still in progress');
      return;
    }
    running = true;
    try {
      const kill = bot.isKillSwitchActive();
      if (!kill && wasKill) {
        blockedLogged.clear();
      }
      wasKill = kill;

      if (kill) {
        const jobs = getPendingJobs();
        for (const job of jobs) {
          // Leave status PENDING so jobs run after resume
          if (!blockedLogged.has(job.id)) {
            const payload = JSON.parse(job.payload) as BroadcastPayload;
            insertDispatchLog(
              uuidv4(),
              typeLabel(job.type),
              summarize(payload, job.type),
              'BLOCKED',
              [process.env.GROUP_A_ID ?? '', process.env.GROUP_B_ID ?? '']
            );
            blockedLogged.add(job.id);
            log.info(`Job ${job.id} blocked by kill switch (left PENDING)`);
          }
        }
        return;
      }

      const jobs = getPendingJobs();
      for (const job of jobs) {
        const payload = JSON.parse(job.payload) as BroadcastPayload;
        log.info(`Executing scheduled job ${job.id} (${job.type})`);

        const result = await bot.broadcast(job.type, payload);

        if (result.blocked) {
          if (!blockedLogged.has(job.id)) {
            insertDispatchLog(
              uuidv4(),
              typeLabel(job.type),
              summarize(payload, job.type),
              'BLOCKED',
              [process.env.GROUP_A_ID ?? '', process.env.GROUP_B_ID ?? '']
            );
            blockedLogged.add(job.id);
          }
          continue; // leave PENDING
        }

        if (result.success) {
          updateJobStatus(job.id, 'DISPATCHED');
          insertDispatchLog(
            uuidv4(),
            typeLabel(job.type),
            summarize(payload, job.type),
            'SUCCESS',
            [process.env.GROUP_A_ID ?? '', process.env.GROUP_B_ID ?? '']
          );
        } else {
          // If client not ready, leave PENDING so it retries next minute
          if (result.error?.includes('not ready') || result.error?.includes('not configured')) {
            log.warn(`Job ${job.id} deferred: ${result.error}`);
            continue;
          }
          updateJobStatus(job.id, 'FAILED');
          insertDispatchLog(
            uuidv4(),
            typeLabel(job.type),
            summarize(payload, job.type) + (result.error ? ` | ${result.error}` : ''),
            'FAILED',
            [process.env.GROUP_A_ID ?? '', process.env.GROUP_B_ID ?? '']
          );
        }

        cleanupFile(payload.filePath);
      }
    } catch (err) {
      log.error('Scheduler tick error', err instanceof Error ? err.message : String(err));
    } finally {
      running = false;
    }
  });

  log.info('Scheduler started (every minute)');
}

export function stopScheduler(): void {
  if (task) {
    task.stop();
    task = null;
    log.info('Scheduler stopped');
  }
}

export function isSchedulerBusy(): boolean {
  return running;
}

export function cancelJob(jobId: string): boolean {
  const job = getJobById(jobId);
  if (!job || job.status !== 'PENDING') {
    return false;
  }
  updateJobStatus(jobId, 'CANCELLED');
  blockedLogged.delete(jobId);
  try {
    const payload = JSON.parse(job.payload) as BroadcastPayload;
    cleanupFile(payload.filePath);
  } catch {
    // ignore
  }
  return true;
}
