import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { verify } from 'hono/jwt';
import { Env } from '@/types/env';
import { AuthService } from '@/services/authService';
import { createProtectedRoute } from '@/middleware/authFactory';

const profileAuth = new Hono<{ Bindings: Env }>()
  .use('*', createProtectedRoute());

// 用戶資料路由
profileAuth.get('/me', async (c) => {
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

export default profileAuth;
