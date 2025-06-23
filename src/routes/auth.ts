import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { verify } from 'hono/jwt';
import { Env } from '../types/env';
import { AuthService } from '../services/authService';
import { createAuthMiddleware } from '../middleware/auth';

const auth = new Hono<{ Bindings: Env }>();

// 登入路由
auth.post('/login', async (c) => {
  try {
    const { email, password } = await c.req.json();

    if (!email || !password) {
      return c.json({ error: '缺少電子郵件或密碼' }, 400);
    }

    const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
    const result = await authService.login(email, password);

    setCookie(c, 'sso_token', result.token, {
      httpOnly: true,
      path: '/',
      maxAge: 86400
    });

    return c.json({ token: result.token });
  } catch (error) {
    return c.json({ error: error instanceof Error ? error.message : '登入失敗' }, 401);
  }
});

// 註冊路由
auth.post('/register', async (c) => {
  try {
    const { email, password } = await c.req.json();

    if (!email || !password) {
      return c.json({ error: '缺少電子郵件或密碼' }, 400);
    }

    const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
    const result = await authService.register(email, password);

    return c.json(result, 201);
  } catch (error) {
    return c.json({ error: error instanceof Error ? error.message : '註冊失敗' }, 409);
  }
});

// 需要認證的路由組
const protectedAuth = new Hono<{ Bindings: Env }>()
  .use('*', async (c, next) => {
    try {
      const jwtMiddleware = createAuthMiddleware(c.env.JWT_SECRET || 'dev_secret_123');
      return await jwtMiddleware(c, next);
    } catch (e) {
      return c.json({ error: '未授權' }, 401);
    }
  });

// 驗證令牌路由
protectedAuth.get('/verify', async (c) => {
  try {
    const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
    const result = await authService.verifyToken(c);
    return c.json(result);
  } catch (error) {
    return c.json({ 
      valid: false, 
      error: error instanceof Error ? error.message : '驗證失敗' 
    }, 401);
  }
});

// 登出路由
protectedAuth.post('/logout', async (c) => {
  try {
    const token = getCookie(c, 'sso_token');
    
    if (!token) {
      return c.json({ error: '無效令牌' }, 400);
    }

    const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
    await authService.logout(token);

    setCookie(c, 'sso_token', '', {
      path: '/',
      expires: new Date(0)
    });

    return c.json({ success: true });
  } catch (error) {
    return c.json({ 
      error: error instanceof Error ? error.message : '登出失敗' 
    }, 500);
  }
});

// 用戶資料路由
protectedAuth.get('/me', async (c) => {
  try {
    const token = getCookie(c, 'sso_token');
    
    if (!token) {
      return c.json({ error: '無效令牌' }, 401);
    }

    const payload = await verify(token, c.env.JWT_SECRET || 'dev_secret_123');
    
    const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
    const user = await authService.getUserInfo(payload.sub as string);

    return c.json(user);
  } catch (error) {
    return c.json({ 
      error: error instanceof Error ? error.message : '獲取用戶資料失敗' 
    }, 401);
  }
});

// 合併路由
auth.route('/', protectedAuth);

export default auth;