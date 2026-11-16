import http from 'node:http';
import {readFileSync, readdirSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {lookup} from './virustotal.mjs';
import {checkGemini, localReview} from './check.mjs';

// ---- configuration (all optional) ----
// PORT, HOST            where to listen (Render sets PORT; HOST defaults to 0.0.0.0 on Render, 127.0.0.1 locally)
// PUBLIC_URL            public address if hosted somewhere other than Render (Render's own URL is detected automatically)
// GEMINI_API_KEY        Google AI Studio key; without it the local check is used
// VIRUSTOTAL_API_KEY    VirusTotal key; without it link reports are skipped
// STAFF_TOKEN           secret for the expert desk link (16+ characters); random on every start if not set
const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1');
const origins = new Set(['http://127.0.0.1:' + port, 'http://localhost:' + port]);
for (const u of [process.env.PUBLIC_URL, process.env.RENDER_EXTERNAL_URL]) if (u) try { origins.add(new URL(u).origin); } catch {}
const hosts = new Set([...origins].map(o => new URL(o).host));
const base = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'http://127.0.0.1:' + port;

const key = (process.env.GEMINI_API_KEY || '').trim();
const vtKey = (process.env.VIRUSTOTAL_API_KEY || '').trim();
const envToken = (process.env.STAFF_TOKEN || '').trim();
const staff = envToken.length >= 16 ? envToken : randomUUID();
if (envToken && envToken.length < 16) console.warn('STAFF_TOKEN is shorter than 16 characters, a random one is used instead.');

const cases = new Map(), checks = [];
const page = readFileSync(new URL('index.html', import.meta.url)), desk = readFileSync(new URL('expert.html', import.meta.url));
const TYPES = {png: 'image/png', svg: 'image/svg+xml', webp: 'image/webp'};
const assets = new Map();
for (const name of readdirSync(new URL('assets/', import.meta.url))) {
  const ext = name.split('.').pop();
  if (TYPES[ext] && /^[a-z0-9-]+\.[a-z]+$/.test(name)) assets.set('/assets/' + name, {body: readFileSync(new URL('assets/' + name, import.meta.url)), type: TYPES[ext]});
}

const failure = (status, message) => Object.assign(new Error(message), {status});
async function analyze(message, kind) {
  const now = Date.now();
  while (checks.length && checks[0] < now - 60000) checks.shift();
  if (checks.length >= 12) return {source: 'local', notice: 'Демо достигло лимита ИИ-проверок в минуту — показана локальная проверка. Попробуйте чуть позже.', ...localReview(message, kind)};
  checks.push(now);
  return checkGemini(key, message, kind);
}

const security = {'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY'};

http.createServer(async (req, res) => {
  const reply = (status, data, type = 'application/json') => {
    res.writeHead(status, {'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store', ...security});
    res.end(type === 'application/json' ? JSON.stringify(data) : data);
  };
  try {
    const path = (req.url || '/').split('?')[0];
    if (req.method === 'GET' && path === '/healthz') return reply(200, 'ok', 'text/plain');
    if (!hosts.has(req.headers.host)) throw failure(403, 'Откройте демо по его официальному адресу.');
    if (req.method === 'GET' && (path === '/' || path === '/expert')) return reply(200, path === '/' ? page : desk, 'text/html');
    if (req.method === 'GET' && assets.has(path)) {
      const a = assets.get(path);
      res.writeHead(200, {'Content-Type': a.type, 'Cache-Control': 'public, max-age=86400', ...security});
      return res.end(a.body);
    }
    if (req.method === 'GET' && path === '/favicon.ico') { res.writeHead(301, {Location: '/assets/favicon.svg'}); return res.end(); }
    if (req.method !== 'POST' || !origins.has(req.headers.origin) || req.headers['content-type'] !== 'application/json') throw failure(req.method === 'GET' ? 404 : 403, req.method === 'GET' ? 'Страница не найдена.' : 'Откройте демо по его официальному адресу.');

    let bytes = 0, chunks = [];
    for await (const chunk of req) { bytes += chunk.length; if (bytes > 32768) throw failure(413, 'Слишком большой запрос.'); chunks.push(chunk); }
    let data;
    try { data = JSON.parse(Buffer.concat(chunks)); } catch { throw failure(400, 'Некорректный запрос.'); }
    function field(name, max) {
      const v = data?.[name];
      if (typeof v !== 'string' || !v.trim() || v.length > max) throw failure(400, 'Проверьте введённый текст.');
      return v.trim();
    }

    if (path === '/api/check') {
      const message = field('message', 5000), kind = field('kind', 32);
      const [assessment, virusTotal] = await Promise.all([analyze(message, kind), lookup(message, kind, vtKey)]);
      return reply(200, {...assessment, virusTotal});
    }
    if (path === '/api/cases') {
      if (cases.size >= 200) throw failure(429, 'Очередь демо переполнена.');
      const id = randomUUID();
      const verdict = ['high', 'medium', 'low', 'unknown'].includes(data.verdict) ? data.verdict : '';
      cases.set(id, {id, summary: field('summary', 5000), verdict, created: Date.now(), answer: '', answered: 0});
      return reply(201, {id});
    }
    if (path === '/api/status') {
      const entry = cases.get(data.id);
      if (!entry) throw failure(404, 'Обращение не найдено (сервер мог перезапуститься).');
      return reply(200, {answer: entry.answer});
    }

    if (req.headers.authorization !== 'Bearer ' + staff) throw failure(403, 'Нужна личная ссылка специалиста (с кодом после #).');
    if (path === '/api/queue') return reply(200, [...cases.values()].reverse());
    if (path === '/api/reply') {
      const entry = cases.get(data.id);
      if (!entry) throw failure(404, 'Обращение не найдено.');
      entry.answer = field('answer', 4000); entry.answered = Date.now();
      return reply(200, {ok: true});
    }
    throw failure(404, 'Страница не найдена.');
  } catch (e) {
    reply(e.status || 503, {error: e.status ? e.message : 'Сервис временно недоступен. Попробуйте ещё раз или напишите специалисту.'});
  }
}).listen(port, host, () => {
  console.log('Digital Shield запущен.');
  console.log('Gemini: ' + (key ? 'ключ задан' : 'нет ключа (локальная проверка)') + ' · VirusTotal: ' + (vtKey ? 'ключ задан' : 'нет ключа'));
  console.log('Сайт для клиентов:        ' + base);
  console.log('Рабочее место специалиста: ' + base + '/expert#' + staff);
});
