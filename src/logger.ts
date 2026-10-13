type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<Level, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const MIN_LEVEL: Level = (process.env.LOG_LEVEL as Level) || 'info';

function ts(): string {
  return new Date().toISOString();
}

function emit(level: Level, msg: string, meta?: unknown): void {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[MIN_LEVEL]) return;
  const line =
    meta !== undefined
      ? `${ts()} [${level.toUpperCase()}] ${msg} ${typeof meta === 'string' ? meta : JSON.stringify(meta)}`
      : `${ts()} [${level.toUpperCase()}] ${msg}`;
  if (level === 'error') {
    console.error(line);
  } else if (level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export const log = {
  debug: (msg: string, meta?: unknown) => emit('debug', msg, meta),
  info: (msg: string, meta?: unknown) => emit('info', msg, meta),
  warn: (msg: string, meta?: unknown) => emit('warn', msg, meta),
  error: (msg: string, meta?: unknown) => emit('error', msg, meta),
};
