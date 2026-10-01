const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Redis = require('ioredis');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@college.edu').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@123';

const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2, enableReadyCheck: true });

app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const now = () => new Date().toISOString();
const id = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const userKey = email => 'tiku:user:' + email.toLowerCase();
const qKey = qid => 'tiku:q:' + qid;

function sign(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
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

function admin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ message: '需要管理员权限' });
  next();
}

async function getQuestion(qid) {
  const data = await redis.hgetall(qKey(qid));
  if (!data || !data.id) return null;
  return { ...data, options: JSON.parse(data.options || '[]') };
}

async function listQuestions() {
  const ids = await redis.smembers('tiku:questions');
  const rows = await Promise.all(ids.map(getQuestion));
  return rows.filter(Boolean).sort((a,b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
}

async function saveQuestion(q) {
  const row = {
    id: q.id || id(),
    category: (q.category || '综合').trim(),
    question: (q.question || '').trim(),
    options: JSON.stringify(Array.isArray(q.options) ? q.options : []),
    answer: (q.answer || '').trim(),
    explanation: (q.explanation || '').trim(),
    createdAt: q.createdAt || now(),
    updatedAt: now()
  };
  await redis.hset(qKey(row.id), row);
  await redis.sadd('tiku:questions', row.id);
  await redis.sadd('tiku:categories', row.category);
  return { ...row, options: JSON.parse(row.options) };
}

async function ensureSeed() {
  const hasAdmin = await redis.exists(userKey(ADMIN_EMAIL));
  if (!hasAdmin) {
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await redis.hset(userKey(ADMIN_EMAIL), {
      id: 'admin',
      name: '管理员',
      email: ADMIN_EMAIL,
      passwordHash,
      role: 'admin',
      createdAt: now()
    });
  }
  const count = await redis.scard('tiku:questions');
  if (count === 0) {
    const seed = [
      ['计算机基础','HTML 的主要作用是什么？',['定义网页结构','管理数据库','编译 Java','压缩图片'],'定义网页结构','HTML 用于描述网页内容和结构。'],
      ['计算机基础','HTTP 状态码 404 通常表示什么？',['服务器错误','未找到资源','请求成功','永久重定向'],'未找到资源','404 表示服务器没有找到请求的资源。'],
      ['计算机基础','JavaScript 中严格相等运算符是？',['=','==','===','!='],'===','=== 会同时比较值和类型。'],
      ['计算机基础','SQL 中用于查询数据的关键字是？',['SELECT','UPDATE','DELETE','DROP'],'SELECT','SELECT 用于读取数据。'],
      ['数学','圆的面积公式是？',['2πr','πr²','πd','r²/2'],'πr²','圆面积等于 π 乘半径平方。'],
      ['数学','2 的 5 次方等于多少？',['10','16','25','32'],'32','2×2×2×2×2=32。'],
      ['数学','一元二次方程 ax²+bx+c=0 的判别式是？',['b²-4ac','a²-4bc','b²+4ac','2a+b'],'b²-4ac','判别式 Δ=b²-4ac。'],
      ['英语','“benefit” 最接近的中文意思是？',['利益/好处','危险','限制','成本'],'利益/好处','benefit 可表示好处、益处。'],
      ['英语','“go” 的过去式是？',['goed','gone','went','going'],'went','go 的过去式为 went，过去分词为 gone。'],
      ['常识','水在标准大气压下的沸点约为？',['0°C','50°C','100°C','150°C'],'100°C','标准大气压下水的沸点约为 100°C。'],
      ['常识','地球绕太阳一周约需要？',['24小时','30天','365天','10年'],'365天','地球公转周期约为一年。'],
      ['逻辑','若所有 A 都是 B，且所有 B 都是 C，则？',['所有 A 都是 C','所有 C 都是 A','没有 A 是 C','无法判断'],'所有 A 都是 C','这是集合包含关系的传递性。']
    ];
    for (const s of seed) await saveQuestion({ category:s[0], question:s[1], options:s[2], answer:s[3], explanation:s[4] });
  }
}

app.get('/api/health', async (req,res) => {
  try {
    await redis.ping();
    res.json({ ok:true, storage:'redis', time:now() });
  } catch (e) {
    res.status(500).json({ ok:false, message:e.message });
  }
});

app.post('/api/auth/register', async (req,res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!name || !email || password.length < 6) return res.status(400).json({ message:'请输入姓名、邮箱，密码至少 6 位' });
  if (await redis.exists(userKey(email))) return res.status(409).json({ message:'该邮箱已经注册' });
  const user = { id:id(), name, email, role:'user', createdAt:now() };
  const passwordHash = await bcrypt.hash(password, 10);
  await redis.hset(userKey(email), { ...user, passwordHash });
  res.json({ token:sign(user), user });
});

app.post('/api/auth/login', async (req,res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const row = await redis.hgetall(userKey(email));
  if (!row || !row.email || !(await bcrypt.compare(password, row.passwordHash || ''))) {
    return res.status(401).json({ message:'邮箱或密码错误' });
  }
  const user = { id:row.id, name:row.name, email:row.email, role:row.role || 'user' };
  res.json({ token:sign(user), user });
});

app.get('/api/auth/me', auth, (req,res) => res.json({ user:req.user }));

app.get('/api/categories', async (req,res) => {
  const categories = (await redis.smembers('tiku:categories')).sort();
  res.json({ categories });
});

app.get('/api/questions', async (req,res) => {
  const search = String(req.query.search || '').trim().toLowerCase();
  const category = String(req.query.category || '').trim();
  let rows = await listQuestions();
  if (category) rows = rows.filter(q => q.category === category);
  if (search) rows = rows.filter(q => (q.question + ' ' + q.answer + ' ' + q.explanation).toLowerCase().includes(search));
  res.json({ questions:rows.slice(0,200), total:rows.length });
});

app.get('/api/questions/:id', async (req,res) => {
  const q = await getQuestion(req.params.id);
  if (!q) return res.status(404).json({ message:'题目不存在' });
  res.json({ question:q });
});

app.get('/api/quiz/random', async (req,res) => {
  const category = String(req.query.category || '').trim();
  const limit = Math.max(1, Math.min(50, Number(req.query.limit || 10)));
  let rows = await listQuestions();
  if (category) rows = rows.filter(q => q.category === category);
  rows.sort(() => Math.random() - 0.5);
  res.json({ questions:rows.slice(0,limit) });
});

app.post('/api/questions', auth, admin, async (req,res) => {
  if (!req.body.question || !req.body.answer) return res.status(400).json({ message:'题目和答案不能为空' });
  const q = await saveQuestion(req.body);
  res.json({ question:q });
});

app.put('/api/questions/:id', auth, admin, async (req,res) => {
  const old = await getQuestion(req.params.id);
  if (!old) return res.status(404).json({ message:'题目不存在' });
  const q = await saveQuestion({ ...old, ...req.body, id:old.id, createdAt:old.createdAt });
  res.json({ question:q });
});

app.delete('/api/questions/:id', auth, admin, async (req,res) => {
  await redis.del(qKey(req.params.id));
  await redis.srem('tiku:questions', req.params.id);
  res.json({ ok:true });
});

app.post('/api/import', auth, admin, async (req,res) => {
  const questions = Array.isArray(req.body.questions) ? req.body.questions : [];
  if (!questions.length) return res.status(400).json({ message:'questions 数组不能为空' });
  let imported = 0;
  for (const q of questions.slice(0,1000)) {
    if (q.question && q.answer) { await saveQuestion(q); imported++; }
  }
  res.json({ ok:true, imported });
});

app.get('/api/favorites', auth, async (req,res) => {
  const ids = await redis.smembers('tiku:fav:' + req.user.id);
  const rows = (await Promise.all(ids.map(getQuestion))).filter(Boolean);
  res.json({ questions:rows });
});

app.post('/api/favorites/:id', auth, async (req,res) => {
  const key = 'tiku:fav:' + req.user.id;
  const exists = await redis.sismember(key, req.params.id);
  if (exists) await redis.srem(key, req.params.id); else await redis.sadd(key, req.params.id);
  res.json({ favorite:!exists });
});

app.get('/api/wrong', auth, async (req,res) => {
  const ids = await redis.smembers('tiku:wrong:' + req.user.id);
  const rows = (await Promise.all(ids.map(getQuestion))).filter(Boolean);
  res.json({ questions:rows });
});

app.post('/api/wrong/:id', auth, async (req,res) => {
  await redis.sadd('tiku:wrong:' + req.user.id, req.params.id);
  res.json({ ok:true });
});

app.delete('/api/wrong/:id', auth, async (req,res) => {
  await redis.srem('tiku:wrong:' + req.user.id, req.params.id);
  res.json({ ok:true });
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

redis.on('error', err => console.error('Redis error:', err.message));

ensureSeed().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log('TikuGo running on port ' + PORT));
}).catch(err => {
  console.error(err);
  process.exit(1);
});
