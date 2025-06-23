import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import { Env } from '@/types/env';
import { AuthService } from '@/services/authService';

const publicAuth = new Hono<{ Bindings: Env }>();

publicAuth.post('/login', async (c) => {
  try {
    const { email, password } = await c.req.json();

    if (!email || !password) {
      return c.json({ error: '缺少電子郵件或密碼' }, 400);
    }

    const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
    const result = await authService.login(email, password);

    // 設置 access token
    setCookie(c, 'sso_token', result.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 900 // 15分鐘
    });

    // 設置 refresh token  
    setCookie(c, 'sso_refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 604800 // 7天
    });

    return c.json({
      message: '登入成功',
      user: result.user
    });
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
