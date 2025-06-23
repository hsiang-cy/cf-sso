import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import { Env } from '@/types/env';
import { AuthService } from '@/services/authService';

const publicAuth = new Hono<{ Bindings: Env }>();

// 登入路由
publicAuth.post('/login', async (c) => {
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
publicAuth.post('/register', async (c) => {
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

export default publicAuth;
