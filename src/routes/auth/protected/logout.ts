import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { Env } from '@/types/env';
import { AuthService } from '@/services/authService';

const logoutRoutes = new Hono<{ Bindings: Env }>()

// 登出路由
logoutRoutes.post('/logout', async (c) => {
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

export default logoutRoutes;
