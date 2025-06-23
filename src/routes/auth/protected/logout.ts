import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { Env } from '@/types/env';
import { AuthService } from '@/services/authService';

const logoutRoutes = new Hono<{ Bindings: Env }>();

logoutRoutes.post('/logout', async (c) => {
  try {
    const refreshToken = getCookie(c, 'sso_refresh_token');
    
    // 清除數據庫中的 refresh token
    if (refreshToken) {
      const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
      await authService.logout(refreshToken);
    }

    // 清除所有相關 cookies
    setCookie(c, 'sso_token', '', {
      path: '/',
      expires: new Date(0),
      httpOnly: true
    });

    setCookie(c, 'sso_refresh_token', '', {
      path: '/',
      expires: new Date(0),
      httpOnly: true
    });

    return c.json({ success: true });
  } catch (error) {
    return c.json({ 
      error: error instanceof Error ? error.message : '登出失敗' 
    }, 500);
  }
});

export default logoutRoutes;