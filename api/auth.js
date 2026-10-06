// HR Operations Platform — 로그인·가입·관리자 서버 기능 (Vercel Serverless Function)
// 저장소: Vercel Marketplace의 Upstash for Redis (KV_REST_API_URL / KV_REST_API_TOKEN 자동 설정)
// 외부 패키지 없이 Node 기본 기능만 쓴다.
const crypto = require('crypto');

const DEFAULT_ADMIN_PASSWORD = '2026';          // 처음 관리자 비밀번호 (관리자 화면에서 바꿀 수 있음)
const TEAMS = ['인재사업 1팀', '인재사업 2팀'];
const DEPTS = ['HR-Biz'];
const USER_SESSION_HOURS = 12;
const ADMIN_SESSION_HOURS = 2;
const K = { admin: 'hrp:admin', code: 'hrp:code', allow: 'hrp:allow', users: 'hrp:users', secret: 'hrp:secret' };

/* ---------- Redis (Upstash REST) ---------- */
function redisConf() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url: url.replace(/\/$/, ''), token } : null;
}
async function redis(...cmd) {
  const c = redisConf();
  if (!c) { const e = new Error('storage_missing'); e.status = 503; throw e; }
  const r = await fetch(c.url, { method: 'POST', headers: { Authorization: `Bearer ${c.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(cmd) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) { const e = new Error('storage_error: ' + (j.error || r.status)); e.status = 502; throw e; }
  return j.result;
}
const getJSON = async (key, fallback) => { const v = await redis('GET', key); if (v == null) return fallback; try { return JSON.parse(v); } catch { return fallback; } };
const setJSON = (key, val) => redis('SET', key, JSON.stringify(val));

/* ---------- 암호 ---------- */
function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 32).toString('hex');
  return { salt, hash };
}
function checkPassword(pw, rec) {
  if (!rec || !rec.salt || !rec.hash) return false;
  const a = Buffer.from(hashPassword(pw, rec.salt).hash, 'hex'), b = Buffer.from(rec.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function secret() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  let s = await redis('GET', K.secret);
  if (!s) { s = crypto.randomBytes(32).toString('hex'); await redis('SET', K.secret, s, 'NX'); s = await redis('GET', K.secret); }
  return s;
}
const b64u = buf => Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
async function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const sig = b64u(crypto.createHmac('sha256', await secret()).update(body).digest());
  return `${body}.${sig}`;
}
async function verify(token, kind) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expect = b64u(crypto.createHmac('sha256', await secret()).update(body).digest());
  if (sig.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  let p; try { p = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); } catch { return null; }
  if (!p || p.k !== kind || !p.exp || p.exp < Date.now()) return null;
  return p;
}

/* ---------- 입력 정리 ---------- */
const normEmail = s => String(s || '').trim().toLowerCase();
const normName = s => String(s || '').replace(/\s+/g, '').trim();
const isEmail = s => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const clean = (s, n = 80) => String(s || '').trim().slice(0, n);

/* ---------- 시도 횟수 제한 ---------- */
async function tooMany(kind, id, limit, windowSec) {
  const key = `hrp:fail:${kind}:${id}`;
  const n = +(await redis('GET', key)) || 0;
  return n >= limit;
}
async function fail(kind, id, windowSec) {
  const key = `hrp:fail:${kind}:${id}`;
  const n = await redis('INCR', key);
  if (n === 1) await redis('EXPIRE', key, windowSec);
  return n;
}
const clearFail = (kind, id) => redis('DEL', `hrp:fail:${kind}:${id}`);
function ipOf(req) { return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim(); }

/* ---------- 데이터 ---------- */
async function adminRecord() {
  const rec = await getJSON(K.admin, null);
  return rec || hashPassword(DEFAULT_ADMIN_PASSWORD, 'default-admin-salt');
}
async function allowList() { return await getJSON(K.allow, []); }
async function getUser(email) { const v = await redis('HGET', K.users, email); return v ? JSON.parse(v) : null; }
function findAllowed(list, name, email) { return list.find(a => a.email === email && normName(a.name) === normName(name)); }
const publicUser = u => ({ name: u.name, email: u.email, dept: u.dept, team: u.team });

/* ---------- 응답 ---------- */
function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}
const bad = (res, msg, status = 400, extra = {}) => send(res, status, { ok: false, error: msg, ...extra });
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return {}; } }
  const chunks = []; for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { return {}; }
}
function bearer(req) { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7) : ''; }

/* ---------- 동작 ---------- */
const actions = {
  async status() {
    if (!redisConf()) return { ok: true, ready: false };
    const code = await redis('GET', K.code);
    return { ok: true, ready: true, codeSet: !!code, teams: TEAMS, depts: DEPTS };
  },

  async login(b, req) {
    const email = normEmail(b.email), team = clean(b.team), dept = clean(b.dept);
    if (!email || !b.password) throw Object.assign(new Error('사내메일과 비밀번호를 입력해주세요.'), { status: 400 });
    if (await tooMany('login', email, 5)) throw Object.assign(new Error('로그인 실패가 5번 넘어 10분 동안 막혔습니다. 잠시 후 다시 시도해주세요.'), { status: 429 });
    const u = await getUser(email);
    if (!u || !checkPassword(b.password, u)) { const n = await fail('login', email, 600); throw Object.assign(new Error(`사내메일 또는 비밀번호가 맞지 않습니다. (${n}/5)`), { status: 401 }); }
    const allowed = findAllowed(await allowList(), u.name, email);
    if (!allowed) throw Object.assign(new Error('가입 허용 명단에서 빠진 계정입니다. 관리자에게 문의해주세요.'), { status: 403 });
    if (dept && dept !== u.dept) throw Object.assign(new Error(`사업부가 가입 정보(${u.dept})와 다릅니다.`), { status: 400 });
    if (team && team !== u.team) throw Object.assign(new Error(`소속이 가입 정보(${u.team})와 다릅니다.`), { status: 400 });
    await clearFail('login', email);
    const token = await sign({ k: 'user', e: email, exp: Date.now() + USER_SESSION_HOURS * 3600e3 });
    return { ok: true, token, user: publicUser(u) };
  },

  async me(b, req) {
    const p = await verify(bearer(req), 'user');
    if (!p) throw Object.assign(new Error('다시 로그인해주세요.'), { status: 401 });
    const u = await getUser(p.e);
    if (!u || !findAllowed(await allowList(), u.name, u.email)) throw Object.assign(new Error('사용할 수 없는 계정입니다.'), { status: 403 });
    return { ok: true, user: publicUser(u) };
  },

  // 가입 1단계: 관리자 명단과 이름·메일이 맞는지
  async signupCheck(b, req) {
    const name = clean(b.name, 40), email = normEmail(b.email), team = clean(b.team), dept = clean(b.dept);
    if (!name || !isEmail(email)) throw Object.assign(new Error('이름과 사내메일 주소를 정확히 입력해주세요.'), { status: 400 });
    if (!DEPTS.includes(dept)) throw Object.assign(new Error('사업부를 선택해주세요.'), { status: 400 });
    if (!TEAMS.includes(team)) throw Object.assign(new Error('소속을 선택해주세요.'), { status: 400 });
    const ip = ipOf(req);
    if (await tooMany('check', ip, 20)) throw Object.assign(new Error('시도가 너무 많습니다. 15분 뒤에 다시 시도해주세요.'), { status: 429 });
    const a = findAllowed(await allowList(), name, email);
    if (!a) { await fail('check', ip, 900); throw Object.assign(new Error('가입 허용 명단에 없는 이름 또는 메일입니다. 관리자에게 등록을 요청해주세요.'), { status: 403 }); }
    if (a.team && a.team !== team) throw Object.assign(new Error(`소속이 명단과 다릅니다. (${a.team})`), { status: 400 });
    if (!(await redis('GET', K.code))) throw Object.assign(new Error('관리자가 아직 가입 코드를 정하지 않았습니다. 관리자에게 문의해주세요.'), { status: 409 });
    const existing = await getUser(email);
    return { ok: true, existing: !!existing };
  },

  // 가입 2단계: 관리자가 정한 4자리 코드
  async signupVerify(b, req) {
    const name = clean(b.name, 40), email = normEmail(b.email), team = clean(b.team), dept = clean(b.dept);
    const a = findAllowed(await allowList(), name, email);
    if (!a || !TEAMS.includes(team) || !DEPTS.includes(dept)) throw Object.assign(new Error('가입 정보를 처음부터 다시 입력해주세요.'), { status: 400 });
    if (await tooMany('code', email, 5)) throw Object.assign(new Error('가입 코드를 5번 틀려 15분 동안 막혔습니다.'), { status: 429 });
    const code = await redis('GET', K.code);
    if (!code || String(b.code || '').trim() !== code) { const n = await fail('code', email, 900); throw Object.assign(new Error(`가입 코드가 맞지 않습니다. (${n}/5)`), { status: 401 }); }
    await clearFail('code', email);
    const ticket = await sign({ k: 'signup', e: email, n: a.name, t: team, d: dept, exp: Date.now() + 15 * 60e3 }); // 이름은 관리자 명단 표기 그대로
    return { ok: true, ticket };
  },

  // 가입 3단계: 비밀번호 정하기 (이미 가입한 사람이면 비밀번호 재설정)
  async signupComplete(b) {
    const p = await verify(b.ticket, 'signup');
    if (!p) throw Object.assign(new Error('가입 시간이 지났습니다. 처음부터 다시 해주세요.'), { status: 401 });
    const pw = String(b.password || '');
    if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) throw Object.assign(new Error('비밀번호는 영문과 숫자를 섞어 8자 이상으로 정해주세요.'), { status: 400 });
    const old = await getUser(p.e);
    const u = { name: p.n, email: p.e, dept: p.d, team: p.t, ...hashPassword(pw), createdAt: old?.createdAt || new Date().toISOString(), updatedAt: new Date().toISOString() };
    await redis('HSET', K.users, p.e, JSON.stringify(u));
    await clearFail('login', p.e);
    const token = await sign({ k: 'user', e: p.e, exp: Date.now() + USER_SESSION_HOURS * 3600e3 });
    return { ok: true, token, user: publicUser(u), reset: !!old };
  },

  /* ----- 관리자 ----- */
  async adminLogin(b, req) {
    const ip = ipOf(req);
    if (await tooMany('admin', ip, 5)) throw Object.assign(new Error('관리자 비밀번호를 5번 틀려 15분 동안 막혔습니다.'), { status: 429 });
    if (!checkPassword(String(b.password || ''), await adminRecord())) { const n = await fail('admin', ip, 900); throw Object.assign(new Error(`관리자 비밀번호가 맞지 않습니다. (${n}/5)`), { status: 401 }); }
    await clearFail('admin', ip);
    const isDefault = !(await getJSON(K.admin, null));
    return { ok: true, token: await sign({ k: 'admin', exp: Date.now() + ADMIN_SESSION_HOURS * 3600e3 }), isDefault };
  },
  async adminGet() {
    const [allow, code, usersRaw] = await Promise.all([allowList(), redis('GET', K.code), redis('HGETALL', K.users)]);
    const users = [];
    for (let i = 0; i < (usersRaw || []).length; i += 2) { try { const u = JSON.parse(usersRaw[i + 1]); users.push({ ...publicUser(u), createdAt: u.createdAt }); } catch {} }
    return { ok: true, allow, code: code || '', users, teams: TEAMS, isDefaultPassword: !(await getJSON(K.admin, null)) };
  },
  async adminSetCode(b) {
    const code = String(b.code || '').trim();
    if (!/^\d{4}$/.test(code)) throw Object.assign(new Error('가입 코드는 숫자 4자리로 정해주세요.'), { status: 400 });
    await redis('SET', K.code, code);
    return { ok: true, code };
  },
  async adminSetPassword(b) {
    if (!checkPassword(String(b.current || ''), await adminRecord())) throw Object.assign(new Error('현재 관리자 비밀번호가 맞지 않습니다.'), { status: 401 });
    const pw = String(b.next || '');
    if (pw.length < 4) throw Object.assign(new Error('새 관리자 비밀번호는 4자 이상으로 정해주세요.'), { status: 400 });
    await setJSON(K.admin, hashPassword(pw));
    return { ok: true };
  },
  async adminAddAllow(b) {
    const list = await allowList();
    const added = [], skipped = [];
    for (const raw of (Array.isArray(b.entries) ? b.entries : []).slice(0, 500)) {
      const name = clean(raw.name, 40), email = normEmail(raw.email), team = TEAMS.includes(raw.team) ? raw.team : '';
      if (!name || !isEmail(email)) { skipped.push(`${name || '(이름 없음)'} ${email || ''} — 형식 오류`); continue; }
      const i = list.findIndex(a => a.email === email);
      if (i >= 0) list[i] = { ...list[i], name, team }; else list.push({ name, email, team, addedAt: new Date().toISOString() });
      added.push(email);
    }
    await setJSON(K.allow, list);
    return { ok: true, allow: list, added: added.length, skipped };
  },
  async adminRemoveAllow(b) {
    const email = normEmail(b.email);
    const list = (await allowList()).filter(a => a.email !== email);
    await setJSON(K.allow, list);
    if (b.alsoUser) await redis('HDEL', K.users, email);
    return { ok: true, allow: list };
  },
  async adminRemoveUser(b) {
    await redis('HDEL', K.users, normEmail(b.email));
    return { ok: true };
  },
};
const ADMIN_ONLY = new Set(['adminGet', 'adminSetCode', 'adminSetPassword', 'adminAddAllow', 'adminRemoveAllow', 'adminRemoveUser']);

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST' && req.method !== 'GET') return bad(res, 'POST로 요청해주세요.', 405);
  try {
    const b = req.method === 'GET' ? { action: 'status' } : await readBody(req);
    const fn = actions[b.action];
    if (!fn) return bad(res, '알 수 없는 요청입니다.', 400);
    if (b.action !== 'status' && !redisConf()) return bad(res, '서버 저장소가 연결되지 않았습니다. Vercel에서 Upstash for Redis를 연결해주세요.', 503, { code: 'storage_missing' });
    if (ADMIN_ONLY.has(b.action) && !(await verify(bearer(req), 'admin'))) return bad(res, '관리자 로그인이 필요합니다.', 401, { code: 'admin_required' });
    return send(res, 200, await fn(b, req));
  } catch (e) {
    const status = e.status || 500;
    if (status >= 500) console.error(e);
    return bad(res, status >= 500 && !String(e.message).startsWith('storage') ? '서버 오류가 났습니다. 잠시 후 다시 시도해주세요.' : (e.message === 'storage_missing' ? '서버 저장소가 연결되지 않았습니다.' : e.message), status);
  }
};
