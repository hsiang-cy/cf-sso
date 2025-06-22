import { Hono } from 'hono';
import { jwt } from 'hono/jwt';
import { sign, verify } from 'hono/jwt'; // 需要單獨導入 sign 和 verify
import { getCookie, setCookie } from 'hono/cookie'; // 導入 cookie helpers
import { D1Database } from '@cloudflare/workers-types';

type Env = {
  DB: D1Database;
  JWT_SECRET: string;
}

// Helper functions remain the same...
function ab2hex(ab: ArrayBuffer): string {
  return [...new Uint8Array(ab)].map(x => x.toString(16).padStart(2, '0')).join('');
}

function hex2ab(hex: string): ArrayBuffer {
  const view = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return view.buffer;
}

async function hashPassword(password: string, salt?: Uint8Array): Promise<{ hash: string, salt: string }> {
  const saltBuffer = salt || crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  return {
    hash: ab2hex(derivedBits),
    salt: ab2hex(saltBuffer),
  };
}

async function verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
  const { hash: newHash } = await hashPassword(password, new Uint8Array(hex2ab(salt)));
  return newHash === hash;
}

const app = new Hono<{ Bindings: Env }>();

// JWT 中間件
app.use('/*', async (c, next) => {
  // 跳過不需要驗證的路由
  if (c.req.path === '/login' || c.req.path === '/register' || c.req.path === '/dev-test') {
    return await next();
  }

  try {
    const jwtMiddleware = jwt({
      secret: c.env.JWT_SECRET || 'dev_secret_123',
      cookie: 'sso_token',
    });
    return await jwtMiddleware(c, next);
  } catch (e) {
    return c.json({ error: '未授權' }, 401);
  }
});

// 登入路由
app.post('/login', async (c) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.json({ error: '缺少電子郵件或密碼' }, 400);
  }

  // 查找用戶
  const user = await c.env.DB.prepare(
    'SELECT * FROM users WHERE email = ?'
  ).bind(email).first<{ id: string; password_hash: string; salt: string }>();

  if (!user) {
    return c.json({ error: '用戶不存在' }, 401);
  }

  // 驗證密碼
  const valid = await verifyPassword(password, user.password_hash, user.salt);
  if (!valid) {
    return c.json({ error: '密碼錯誤' }, 401);
  }

  // 生成 JWT - 使用正確的 sign 函數
  const payload = {
    sub: user.id,
    exp: Math.floor(Date.now() / 1000) + 86400 // 24小時
  };
  const token = await sign(payload, c.env.JWT_SECRET || 'dev_secret_123');

  // 保存會話
  await c.env.DB.prepare(
    'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
  ).bind(token, user.id, payload.exp).run();

  // 設置 Cookie - 使用 setCookie helper
  setCookie(c, 'sso_token', token, {
    httpOnly: true,
    path: '/',
    maxAge: 86400
  });

  return c.json({ token });
});

// CORS 中間件 - 修正後
app.use('*', async (c, next) => {
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // OPTIONS 請求 - 修正狀態碼
  if (c.req.method === 'OPTIONS') {
    return new Response('', { status: 204 }); // 使用 new Response
  }

  await next();
});

// 需要 JWT 驗證的路由
const authRoutes = app.basePath('/auth')
  .use('*', async (c, next) => {
    try {
      const jwtMiddleware = jwt({
        secret: c.env.JWT_SECRET || 'dev_secret_123',
        cookie: 'sso_token'
      });
      return await jwtMiddleware(c, next);
    } catch (e) {
      return c.json({ error: '未授權' }, 401);
    }
  });

// 驗證令牌路由
authRoutes.get('/verify', async (c) => {
  try {
    // 從 cookie 中獲取 token - 使用 getCookie helper
    const token = getCookie(c, 'sso_token');
    if (!token) {
      return c.json({ valid: false, error: '無效令牌' }, 401);
    }

    // 驗證 JWT - 使用正確的 verify 函數
    const payload = await verify(token, c.env.JWT_SECRET || 'dev_secret_123');

    // 檢查會話是否有效
    const session = await c.env.DB.prepare(
      'SELECT expires_at FROM sessions WHERE token = ?'
    ).bind(token).first<{ expires_at: number }>();

    if (!session || session.expires_at < Date.now()/1000) {
      return c.json({ valid: false, error: '會話已過期' }, 401);
    }

    return c.json({
      valid: true,
      user_id: payload.sub,
      expires: session.expires_at
    });
  } catch (e) {
    return c.json({ valid: false, error: '未授權' }, 401);
  }
});

// 登出路由
authRoutes.post('/logout', async (c) => {
  const token = getCookie(c, 'sso_token'); // 使用 getCookie
  await c.env.DB.prepare(
    'DELETE FROM sessions WHERE token = ?'
  ).bind(token).run();

  // 清除 Cookie - 使用 setCookie
  setCookie(c, 'sso_token', '', {
    path: '/',
    expires: new Date(0) // 設置過期時間為過去
  });

  return c.json({ success: true });
});

// 受保護的路由
app.get('/protected', async (c) => {
  try {
    // 從 cookie 中獲取 token - 使用 getCookie
    const token = getCookie(c, 'sso_token');
    if (!token) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // 驗證 JWT - 使用正確的 verify 函數
    const payload = await verify(token, c.env.JWT_SECRET || 'dev_secret_123');
    return c.json({ message: 'Authenticated!', user_id: payload.sub });
  } catch (e) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
});

// 註冊路由
app.post('/register', async (c) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.json({ error: '缺少電子郵件或密碼' }, 400);
  }

  // 檢查用戶是否已存在
  const existingUser = await c.env.DB.prepare(
    'SELECT id FROM users WHERE email = ?'
  ).bind(email).first();

  if (existingUser) {
    return c.json({ error: '電子郵件已註冊' }, 409);
  }

  // 雜湊密碼
  const { hash, salt } = await hashPassword(password);

  // 創建用戶
  const userId = crypto.randomUUID();
  await c.env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, salt) VALUES (?, ?, ?, ?)'
  ).bind(userId, email, hash, salt).run();

  return c.json({ id: userId, email }, 201);
});

// 用戶資料路由
authRoutes.get('/me', async (c) => {
  try {
    // 從 cookie 中獲取 token
    const token = getCookie(c, 'sso_token');
    if (!token) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // 驗證 JWT
    const payload = await verify(token, c.env.JWT_SECRET || 'dev_secret_123');
    const user = await c.env.DB.prepare(
      'SELECT id, email, created_at FROM users WHERE id = ?'
    ).bind(payload.sub).first();

    if (!user) {
      return c.json({ error: '用戶不存在' }, 404);
    }

    return c.json(user);
  } catch (e) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
});

app.get('/dev-test', (c) => c.text('SSO Local Dev Ready'));

export default app;