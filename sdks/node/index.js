import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const secret = /(?:bearer\s+|gh[pousr]_)[A-Za-z0-9._~+\/-]{12,}|(?:authorization|cookie|x-api-key)\s*[:=]\s*[^\r\n]+/gi;
const email = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const ip = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
function sanitize(value) {
  return JSON.stringify(value, (_key, v) => typeof v === 'string'
    ? v.replace(secret, '<SECRET>').replace(email, '<EMAIL>').replace(ip, '<IP>') : v);
}
/** Writes JSONL locally. It never sends a request or reads environment values. */
export function captureError(error, context = {}, options = {}) {
  const file = resolve(options.file ?? '.faultnest/requests.jsonl');
  mkdirSync(dirname(file), { recursive: true });
  const event = { timestamp: new Date().toISOString(), error: { name: error?.name, message: error?.message, stack: error?.stack }, context };
  appendFileSync(file, `${sanitize(event)}\n`, { mode: 0o600 });
  return file;
}
