const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Redis = require('ioredis');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const DATABASE_URL = process.env.DATABASE_URL || '';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@college.edu').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@123';
const SCHEMA = 'tiku_go';

const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2, enableReadyCheck: true });
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL }) : null;

app.use(express.json({ limit: '6mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const now = () => new Date().toISOString();
const makeId = () => Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
const userKey = email => 'tiku:user:' + String(email).toLowerCase();
const qKey = id => 'tiku:q:' + id;
const codeKey = code => 'tiku:code:' + code;

function sign(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function membershipOf(user) {
  if (!user) return { active: false, plan: 'free', expiresAt: null };
  if (user.role === 'admin') return { active: true, plan: 'admin', expiresAt: null };
  const raw = user.membershipExpiresAt || user.membership_expires_at || null;
  const active = !!raw && new Date(raw).getTime() > Date.now();
  return {
    active,
    plan: active ? (user.membershipPlan || user.membership_plan || 'vip') : 'free',
    expiresAt: active ? raw : null
  };
}

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ message: '请先登录' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: '登录已过期，请重新登录' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: '需要管理员权限' });
  }
  next();
}

async function vipOnly(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  const user = await getUserByEmail(req.user.email);
  if (!membershipOf(user).active) {
    return res.status(403).json({ message: '此功能需要会员，请先使用激活码开通' });
  }
  next();
}

function mapPgUser(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    email: r.email,
    role: r.role,
    passwordHash: r.password_hash,
    membershipPlan: r.membership_plan,
    membershipExpiresAt: r.membership_expires_at,
    createdAt: r.created_at
  };
}

async function initPostgres() {
  if (!pool) return;
  await pool.query('CREATE SCHEMA IF NOT EXISTS ' + SCHEMA);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      membership_plan TEXT NOT NULL DEFAULT 'free',
      membership_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${SCHEMA}.questions (
      id TEXT PRIMARY KEY,
      category TEXT NOT NULL DEFAULT '综合',
      question TEXT NOT NULL,
      options JSONB NOT NULL DEFAULT '[]'::jsonb,
      answer TEXT NOT NULL,
      explanation TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${SCHEMA}.favorites (
      user_id TEXT NOT NULL,
      question_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, question_id)
    );

    CREATE TABLE IF NOT EXISTS ${SCHEMA}.wrong_questions (
      user_id TEXT NOT NULL,
      question_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, question_id)
    );

    CREATE TABLE IF NOT EXISTS ${SCHEMA}.activation_codes (
      code TEXT PRIMARY KEY,
      days INTEGER NOT NULL,
      plan TEXT NOT NULL DEFAULT 'vip',
      status TEXT NOT NULL DEFAULT 'unused',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      used_by TEXT,
      used_at TIMESTAMPTZ,
      voided_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ${SCHEMA}.membership_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      days INTEGER NOT NULL DEFAULT 0,
      code TEXT,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${SCHEMA}.meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function getUserByEmail(email) {
  email = String(email).toLowerCase();
  if (pool) {
    const { rows } = await pool.query(
      `SELECT * FROM ${SCHEMA}.users WHERE email=$1`,
      [email]
    );
    return mapPgUser(rows[0]);
  }
  const row = await redis.hgetall(userKey(email));
  if (!row || !row.email) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role || 'user',
    passwordHash: row.passwordHash,
    membershipPlan: row.membershipPlan || 'free',
    membershipExpiresAt: row.membershipExpiresAt || null,
    createdAt: row.createdAt
  };
}

async function saveUser(user) {
  if (pool) {
    await pool.query(
      `INSERT INTO ${SCHEMA}.users
      (id,name,email,password_hash,role,membership_plan,membership_expires_at,created_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT(email) DO UPDATE SET
        name=EXCLUDED.name,
        password_hash=EXCLUDED.password_hash,
        role=EXCLUDED.role,
        membership_plan=COALESCE(${SCHEMA}.users.membership_plan, EXCLUDED.membership_plan),
        membership_expires_at=COALESCE(${SCHEMA}.users.membership_expires_at, EXCLUDED.membership_expires_at)`,
      [
        user.id, user.name, user.email.toLowerCase(), user.passwordHash,
        user.role || 'user', user.membershipPlan || 'free',
        user.membershipExpiresAt || null, user.createdAt || now()
      ]
    );
    return;
  }
  await redis.hset(userKey(user.email), {
    id: user.id,
    name: user.name,
    email: user.email.toLowerCase(),
    passwordHash: user.passwordHash,
    role: user.role || 'user',
    membershipPlan: user.membershipPlan || 'free',
    membershipExpiresAt: user.membershipExpiresAt || '',
    createdAt: user.createdAt || now()
  });
  await redis.sadd('tiku:users', user.email.toLowerCase());
}

async function updateMembership(email, plan, expiresAt) {
  email = String(email).toLowerCase();
  if (pool) {
    await pool.query(
      `UPDATE ${SCHEMA}.users
       SET membership_plan=$1, membership_expires_at=$2
       WHERE email=$3`,
      [plan, expiresAt, email]
    );
  } else {
    await redis.hset(userKey(email), {
      membershipPlan: plan,
      membershipExpiresAt: expiresAt || ''
    });
  }
}

async function listUsers() {
  if (pool) {
    const { rows } = await pool.query(
      `SELECT * FROM ${SCHEMA}.users ORDER BY created_at DESC LIMIT 1000`
    );
    return rows.map(mapPgUser);
  }
  let emails = await redis.smembers('tiku:users');
  if (!emails.length) {
    let cursor = '0';
    do {
      const out = await redis.scan(cursor, 'MATCH', 'tiku:user:*', 'COUNT', 200);
      cursor = out[0];
      emails.push(...out[1].map(k => k.slice('tiku:user:'.length)));
    } while (cursor !== '0');
  }
  const rows = await Promise.all([...new Set(emails)].map(getUserByEmail));
  return rows.filter(Boolean);
}

async function getQuestion(id) {
  if (pool) {
    const { rows } = await pool.query(
      `SELECT * FROM ${SCHEMA}.questions WHERE id=$1`,
      [id]
    );
    const q = rows[0];
    if (!q) return null;
    return {
      id: q.id,
      category: q.category,
      question: q.question,
      options: q.options || [],
      answer: q.answer,
      explanation: q.explanation,
      createdAt: q.created_at,
      updatedAt: q.updated_at
    };
  }
  const row = await redis.hgetall(qKey(id));
  if (!row || !row.id) return null;
  return { ...row, options: JSON.parse(row.options || '[]') };
}

async function listQuestions() {
  if (pool) {
    const { rows } = await pool.query(
      `SELECT * FROM ${SCHEMA}.questions ORDER BY created_at DESC`
    );
    return rows.map(q => ({
      id: q.id,
      category: q.category,
      question: q.question,
      options: q.options || [],
      answer: q.answer,
      explanation: q.explanation,
      createdAt: q.created_at,
      updatedAt: q.updated_at
    }));
  }
  const ids = await redis.smembers('tiku:questions');
  const rows = await Promise.all(ids.map(getQuestion));
  return rows.filter(Boolean).sort((a,b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

async function saveQuestion(q) {
  const row = {
    id: q.id || makeId(),
    category: String(q.category || '综合').trim(),
    question: String(q.question || '').trim(),
    options: Array.isArray(q.options) ? q.options : [],
    answer: String(q.answer || '').trim(),
    explanation: String(q.explanation || '').trim(),
    createdAt: q.createdAt || now(),
    updatedAt: now()
  };
  if (pool) {
    await pool.query(
      `INSERT INTO ${SCHEMA}.questions
      (id,category,question,options,answer,explanation,created_at,updated_at)
      VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8)
      ON CONFLICT(id) DO UPDATE SET
        category=EXCLUDED.category,
        question=EXCLUDED.question,
        options=EXCLUDED.options,
        answer=EXCLUDED.answer,
        explanation=EXCLUDED.explanation,
        updated_at=NOW()`,
      [
        row.id, row.category, row.question, JSON.stringify(row.options),
        row.answer, row.explanation, row.createdAt, row.updatedAt
      ]
    );
  } else {
    await redis.hset(qKey(row.id), {
      ...row,
      options: JSON.stringify(row.options)
    });
    await redis.sadd('tiku:questions', row.id);
    await redis.sadd('tiku:categories', row.category);
  }
  return row;
}

async function deleteQuestion(id) {
  if (pool) {
    await pool.query(`DELETE FROM ${SCHEMA}.questions WHERE id=$1`, [id]);
    await pool.query(`DELETE FROM ${SCHEMA}.favorites WHERE question_id=$1`, [id]);
    await pool.query(`DELETE FROM ${SCHEMA}.wrong_questions WHERE question_id=$1`, [id]);
  } else {
    await redis.del(qKey(id));
    await redis.srem('tiku:questions', id);
  }
}

async function getCategories() {
  if (pool) {
    const { rows } = await pool.query(
      `SELECT DISTINCT category FROM ${SCHEMA}.questions ORDER BY category`
    );
    return rows.map(r => r.category);
  }
  return (await redis.smembers('tiku:categories')).sort();
}

async function getRelation(type, userId) {
  if (pool) {
    const table = type === 'fav' ? 'favorites' : 'wrong_questions';
    const { rows } = await pool.query(
      `SELECT q.*
       FROM ${SCHEMA}.${table} x
       JOIN ${SCHEMA}.questions q ON q.id=x.question_id
       WHERE x.user_id=$1
       ORDER BY x.created_at DESC`,
      [userId]
    );
    return rows.map(q => ({
      id: q.id,
      category: q.category,
      question: q.question,
      options: q.options || [],
      answer: q.answer,
      explanation: q.explanation,
      createdAt: q.created_at
    }));
  }
  const ids = await redis.smembers('tiku:' + type + ':' + userId);
  const rows = await Promise.all(ids.map(getQuestion));
  return rows.filter(Boolean);
}

async function toggleFavorite(userId, questionId) {
  if (pool) {
    const ex = await pool.query(
      `SELECT 1 FROM ${SCHEMA}.favorites WHERE user_id=$1 AND question_id=$2`,
      [userId, questionId]
    );
    if (ex.rowCount) {
      await pool.query(
        `DELETE FROM ${SCHEMA}.favorites WHERE user_id=$1 AND question_id=$2`,
        [userId, questionId]
      );
      return false;
    }
    await pool.query(
      `INSERT INTO ${SCHEMA}.favorites(user_id,question_id)
       VALUES($1,$2) ON CONFLICT DO NOTHING`,
      [userId, questionId]
    );
    return true;
  }
  const key = 'tiku:fav:' + userId;
  const ex = await redis.sismember(key, questionId);
  if (ex) await redis.srem(key, questionId);
  else await redis.sadd(key, questionId);
  return !ex;
}

async function setWrong(userId, questionId, add) {
  if (pool) {
    if (add) {
      await pool.query(
        `INSERT INTO ${SCHEMA}.wrong_questions(user_id,question_id)
         VALUES($1,$2) ON CONFLICT DO NOTHING`,
        [userId, questionId]
      );
    } else {
      await pool.query(
        `DELETE FROM ${SCHEMA}.wrong_questions WHERE user_id=$1 AND question_id=$2`,
        [userId, questionId]
      );
    }
  } else {
    if (add) await redis.sadd('tiku:wrong:' + userId, questionId);
    else await redis.srem('tiku:wrong:' + userId, questionId);
  }
}

function makeCode(days) {
  return 'TG-' + days + 'D-' + crypto.randomBytes(5).toString('hex').toUpperCase();
}

async function generateCodes(count, days, plan='vip') {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = makeCode(days);
    if (pool) {
      await pool.query(
        `INSERT INTO ${SCHEMA}.activation_codes(code,days,plan,status)
         VALUES($1,$2,$3,'unused')`,
        [code, days, plan]
      );
    } else {
      await redis.hset(codeKey(code), {
        code,
        days: String(days),
        plan,
        status: 'unused',
        createdAt: now(),
        usedBy: '',
        usedAt: ''
      });
      await redis.sadd('tiku:codes', code);
    }
    codes.push(code);
  }
  return codes;
}

async function listCodes() {
  if (pool) {
    const { rows } = await pool.query(
      `SELECT * FROM ${SCHEMA}.activation_codes
       ORDER BY created_at DESC LIMIT 2000`
    );
    return rows.map(r => ({
      code: r.code,
      days: r.days,
      plan: r.plan,
      status: r.status,
      createdAt: r.created_at,
      usedBy: r.used_by,
      usedAt: r.used_at
    }));
  }
  const codes = await redis.smembers('tiku:codes');
  const rows = await Promise.all(codes.map(c => redis.hgetall(codeKey(c))));
  return rows.filter(r => r.code).sort((a,b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

async function redeemCode(email, code) {
  email = String(email).toLowerCase();
  code = String(code || '').trim().toUpperCase();

  if (pool) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const cr = await client.query(
        `SELECT * FROM ${SCHEMA}.activation_codes
         WHERE code=$1 FOR UPDATE`,
        [code]
      );
      if (!cr.rowCount) throw new Error('激活码不存在');
      const c = cr.rows[0];
      if (c.status !== 'unused') throw new Error('激活码已使用或已作废');

      const ur = await client.query(
        `SELECT * FROM ${SCHEMA}.users WHERE email=$1 FOR UPDATE`,
        [email]
      );
      if (!ur.rowCount) throw new Error('用户不存在');
      const u = ur.rows[0];

      const current = u.membership_expires_at ? new Date(u.membership_expires_at) : null;
      const base = current && current.getTime() > Date.now() ? current : new Date();
      const expiresAt = new Date(base.getTime() + Number(c.days) * 86400000);

      await client.query(
        `UPDATE ${SCHEMA}.users
         SET membership_plan=$1, membership_expires_at=$2
         WHERE email=$3`,
        [c.plan, expiresAt, email]
      );
      await client.query(
        `UPDATE ${SCHEMA}.activation_codes
         SET status='used', used_by=$1, used_at=NOW()
         WHERE code=$2`,
        [email, code]
      );
      await client.query(
        `INSERT INTO ${SCHEMA}.membership_logs
         (id,user_id,action,days,code,note)
         VALUES($1,$2,'activate',$3,$4,$5)`,
        [makeId(), u.id, c.days, code, 'Activation code redeemed']
      );
      await client.query('COMMIT');
      return { plan: c.plan, expiresAt: expiresAt.toISOString() };
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  const c = await redis.hgetall(codeKey(code));
  if (!c || !c.code) throw new Error('激活码不存在');
  if (c.status !== 'unused') throw new Error('激活码已使用或已作废');

  const user = await getUserByEmail(email);
  if (!user) throw new Error('用户不存在');

  const current = user.membershipExpiresAt ? new Date(user.membershipExpiresAt) : null;
  const base = current && current.getTime() > Date.now() ? current : new Date();
  const expiresAt = new Date(base.getTime() + Number(c.days) * 86400000).toISOString();

  await updateMembership(email, c.plan || 'vip', expiresAt);
  await redis.hset(codeKey(code), { status: 'used', usedBy: email, usedAt: now() });
  return { plan: c.plan || 'vip', expiresAt };
}

async function voidCode(code) {
  code = String(code || '').toUpperCase();
  if (pool) {
    await pool.query(
      `UPDATE ${SCHEMA}.activation_codes
       SET status='void', voided_at=NOW()
       WHERE code=$1 AND status='unused'`,
      [code]
    );
  } else {
    const row = await redis.hgetall(codeKey(code));
    if (row && row.code && row.status === 'unused') {
      await redis.hset(codeKey(code), { status: 'void' });
    }
  }
}

async function extendUser(email, days, plan='vip') {
  email = String(email).toLowerCase();
  const user = await getUserByEmail(email);
  if (!user) throw new Error('用户不存在');

  const current = user.membershipExpiresAt ? new Date(user.membershipExpiresAt) : null;
  const base = current && current.getTime() > Date.now() ? current : new Date();
  const expiresAt = new Date(base.getTime() + Number(days) * 86400000).toISOString();

  await updateMembership(email, plan, expiresAt);
  if (pool) {
    await pool.query(
      `INSERT INTO ${SCHEMA}.membership_logs
       (id,user_id,action,days,note)
       VALUES($1,$2,'admin_extend',$3,$4)`,
      [makeId(), user.id, days, 'Admin manual extension']
    );
  }
  return expiresAt;
}

async function migrateRedisToPostgres() {
  if (!pool) return;

  const done = await pool.query(
    `SELECT value FROM ${SCHEMA}.meta WHERE key='redis_migrated_v1'`
  );
  if (done.rowCount) return;

  console.log('Migrating existing TikuGo Redis data into schema tiku_go...');

  let cursor = '0';
  const userKeys = [];
  do {
    const out = await redis.scan(cursor, 'MATCH', 'tiku:user:*', 'COUNT', 200);
    cursor = out[0];
    userKeys.push(...out[1]);
  } while (cursor !== '0');

  for (const key of userKeys) {
    const r = await redis.hgetall(key);
    if (!r.email || !r.passwordHash) continue;
    await saveUser({
      id: r.id || makeId(),
      name: r.name || '用户',
      email: r.email,
      passwordHash: r.passwordHash,
      role: r.role || 'user',
      membershipPlan: r.membershipPlan || 'free',
      membershipExpiresAt: r.membershipExpiresAt || null,
      createdAt: r.createdAt || now()
    });
  }

  const qids = await redis.smembers('tiku:questions');
  for (const qid of qids) {
    const r = await redis.hgetall(qKey(qid));
    if (!r.id || !r.question || !r.answer) continue;
    await saveQuestion({
      id: r.id,
      category: r.category,
      question: r.question,
      options: JSON.parse(r.options || '[]'),
      answer: r.answer,
      explanation: r.explanation || '',
      createdAt: r.createdAt || now()
    });
  }

  for (const key of userKeys) {
    const r = await redis.hgetall(key);
    if (!r.id) continue;

    const favs = await redis.smembers('tiku:fav:' + r.id);
    for (const qid of favs) {
      await pool.query(
        `INSERT INTO ${SCHEMA}.favorites(user_id,question_id)
         VALUES($1,$2) ON CONFLICT DO NOTHING`,
        [r.id, qid]
      );
    }

    const wrongs = await redis.smembers('tiku:wrong:' + r.id);
    for (const qid of wrongs) {
      await pool.query(
        `INSERT INTO ${SCHEMA}.wrong_questions(user_id,question_id)
         VALUES($1,$2) ON CONFLICT DO NOTHING`,
        [r.id, qid]
      );
    }
  }

  await pool.query(
    `INSERT INTO ${SCHEMA}.meta(key,value)
     VALUES('redis_migrated_v1',$1)
     ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`,
    [now()]
  );
  console.log('Redis migration completed.');
}

async function ensureSeed() {
  if (pool) {
    await initPostgres();
    await migrateRedisToPostgres();
  }

  let admin = await getUserByEmail(ADMIN_EMAIL);
  if (!admin) {
    await saveUser({
      id: 'admin',
      name: '管理员',
      email: ADMIN_EMAIL,
      passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 10),
      role: 'admin',
      membershipPlan: 'admin',
      createdAt: now()
    });
  }

  const questions = await listQuestions();
  if (!questions.length) {
    const seed = [
      ['计算机基础','HTML 的主要作用是什么？',['定义网页结构','管理数据库','编译 Java','压缩图片'],'定义网页结构','HTML 用于描述网页内容和结构。'],
      ['计算机基础','HTTP 状态码 404 通常表示什么？',['服务器错误','未找到资源','请求成功','永久重定向'],'未找到资源','404 表示服务器没有找到请求的资源。'],
      ['计算机基础','JavaScript 中严格相等运算符是？',['=','==','===','!='],'===','=== 会同时比较值和类型。'],
      ['数学','圆的面积公式是？',['2πr','πr²','πd','r²/2'],'πr²','圆面积等于 π 乘半径平方。'],
      ['数学','2 的 5 次方等于多少？',['10','16','25','32'],'32','2×2×2×2×2=32。'],
      ['英语','“go” 的过去式是？',['goed','gone','went','going'],'went','go 的过去式为 went。']
    ];
    for (const s of seed) {
      await saveQuestion({
        category: s[0],
        question: s[1],
        options: s[2],
        answer: s[3],
        explanation: s[4]
      });
    }
  }
}

app.get('/api/health', async (req, res) => {
  try {
    if (pool) await pool.query('SELECT 1');
    else await redis.ping();
    res.json({
      ok: true,
      storage: pool ? 'postgres' : 'redis',
      schema: pool ? SCHEMA : null,
      time: now()
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      storage: pool ? 'postgres' : 'redis',
      message: e.message
    });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!name || !email || password.length < 6) {
      return res.status(400).json({ message: '请输入姓名、邮箱，密码至少 6 位' });
    }
    if (await getUserByEmail(email)) {
      return res.status(409).json({ message: '该邮箱已经注册' });
    }

    const user = {
      id: makeId(),
      name,
      email,
      role: 'user',
      membershipPlan: 'free',
      membershipExpiresAt: null,
      createdAt: now()
    };
    await saveUser({ ...user, passwordHash: await bcrypt.hash(password, 10) });

    res.json({
      token: sign(user),
      user: { id:user.id,name:user.name,email:user.email,role:user.role },
      membership: membershipOf(user)
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = await getUserByEmail(email);

  if (!user || !(await bcrypt.compare(password, user.passwordHash || ''))) {
    return res.status(401).json({ message: '邮箱或密码错误' });
  }

  const safe = { id:user.id,name:user.name,email:user.email,role:user.role };
  res.json({
    token: sign(safe),
    user: safe,
    membership: membershipOf(user)
  });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const user = await getUserByEmail(req.user.email);
  res.json({
    user: req.user,
    membership: membershipOf(user),
    storage: pool ? 'postgres' : 'redis',
    schema: pool ? SCHEMA : null
  });
});

app.get('/api/membership', auth, async (req, res) => {
  const user = await getUserByEmail(req.user.email);
  res.json({ membership: membershipOf(user) });
});

app.post('/api/activate', auth, async (req, res) => {
  try {
    const result = await redeemCode(req.user.email, req.body.code);
    res.json({
      ok: true,
      membership: {
        active: true,
        plan: result.plan,
        expiresAt: result.expiresAt
      }
    });
  } catch (e) {
    res.status(400).json({ message: e.message });
  }
});

app.get('/api/categories', async (req, res) => {
  res.json({ categories: await getCategories() });
});

app.get('/api/questions', async (req, res) => {
  const search = String(req.query.search || '').trim().toLowerCase();
  const category = String(req.query.category || '').trim();

  let rows = await listQuestions();
  if (category) rows = rows.filter(q => q.category === category);
  if (search) {
    rows = rows.filter(q =>
      (q.question + ' ' + q.answer + ' ' + q.explanation).toLowerCase().includes(search)
    );
  }
  res.json({ questions: rows.slice(0, 200), total: rows.length });
});

app.get('/api/quiz/random', auth, vipOnly, async (req, res) => {
  const category = String(req.query.category || '').trim();
  const limit = Math.max(1, Math.min(50, Number(req.query.limit || 10)));

  let rows = await listQuestions();
  if (category) rows = rows.filter(q => q.category === category);
  rows.sort(() => Math.random() - 0.5);

  res.json({ questions: rows.slice(0, limit) });
});

app.post('/api/questions', auth, adminOnly, async (req, res) => {
  if (!req.body.question || !req.body.answer) {
    return res.status(400).json({ message: '题目和答案不能为空' });
  }
  res.json({ question: await saveQuestion(req.body) });
});

app.delete('/api/questions/:id', auth, adminOnly, async (req, res) => {
  await deleteQuestion(req.params.id);
  res.json({ ok: true });
});

app.post('/api/import', auth, adminOnly, async (req, res) => {
  const questions = Array.isArray(req.body.questions) ? req.body.questions : [];
  if (!questions.length) {
    return res.status(400).json({ message: 'questions 数组不能为空' });
  }

  let imported = 0;
  for (const q of questions.slice(0, 1000)) {
    if (q.question && q.answer) {
      await saveQuestion(q);
      imported++;
    }
  }
  res.json({ ok: true, imported });
});

app.get('/api/favorites', auth, vipOnly, async (req, res) => {
  res.json({ questions: await getRelation('fav', req.user.id) });
});

app.post('/api/favorites/:id', auth, vipOnly, async (req, res) => {
  res.json({ favorite: await toggleFavorite(req.user.id, req.params.id) });
});

app.get('/api/wrong', auth, vipOnly, async (req, res) => {
  res.json({ questions: await getRelation('wrong', req.user.id) });
});

app.post('/api/wrong/:id', auth, vipOnly, async (req, res) => {
  await setWrong(req.user.id, req.params.id, true);
  res.json({ ok: true });
});

app.delete('/api/wrong/:id', auth, vipOnly, async (req, res) => {
  await setWrong(req.user.id, req.params.id, false);
  res.json({ ok: true });
});

app.get('/api/admin/codes', auth, adminOnly, async (req, res) => {
  res.json({ codes: await listCodes() });
});

app.post('/api/admin/codes/generate', auth, adminOnly, async (req, res) => {
  const count = Math.max(1, Math.min(100, Number(req.body.count || 1)));
  const days = Math.max(1, Math.min(3650, Number(req.body.days || 30)));
  const plan = String(req.body.plan || 'vip');

  res.json({ codes: await generateCodes(count, days, plan) });
});

app.post('/api/admin/codes/void', auth, adminOnly, async (req, res) => {
  await voidCode(req.body.code);
  res.json({ ok: true });
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const users = (await listUsers()).map(u => ({
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    membership: membershipOf(u),
    createdAt: u.createdAt
  }));
  res.json({ users });
});

app.post('/api/admin/users/extend', auth, adminOnly, async (req, res) => {
  try {
    const email = String(req.body.email || '').toLowerCase();
    const days = Math.max(1, Number(req.body.days || 30));
    const expiresAt = await extendUser(email, days, String(req.body.plan || 'vip'));
    res.json({ ok: true, expiresAt });
  } catch (e) {
    res.status(400).json({ message: e.message });
  }
});

app.post('/api/admin/users/revoke', auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase();
  await updateMembership(email, 'free', null);
  const user = await getUserByEmail(email);
  if (pool && user) {
    await pool.query(
      `INSERT INTO ${SCHEMA}.membership_logs
       (id,user_id,action,days,note)
       VALUES($1,$2,'admin_revoke',0,$3)`,
      [makeId(), user.id, 'Admin revoked membership']
    );
  }
  res.json({ ok: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

redis.on('error', err => console.error('Redis error:', err.message));

ensureSeed()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(
        'TikuGo running on port ' + PORT +
        ' using ' + (pool ? 'PostgreSQL schema ' + SCHEMA : 'Redis fallback')
      );
    });
  })
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
