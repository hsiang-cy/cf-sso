import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { Env } from '@/types/env';
import { AuthService } from '@/services/authService';

const refreshAuth = new Hono<{ Bindings: Env }>();

refreshAuth.post('/refresh', async (c) => {
  try {
    const refreshToken = getCookie(c, 'sso_refresh_token');
    
    if (!refreshToken) {
      return c.json({ error: '缺少刷新令牌' }, 401);
    }

    const authService = new AuthService(c.env.DB, c.env.JWT_SECRET || 'dev_secret_123');
    const result = await authService.refreshAccessToken(refreshToken);

    // 設置新的 access token
    setCookie(c, 'sso_token', result.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 900 // 15分鐘
    });

    return c.json({ message: '令牌已刷新' });
  } catch (error) {
    return c.json({ 
      error: error instanceof Error ? error.message : '刷新失敗' 
    }, 401);
  }
});

export default refreshAuth;