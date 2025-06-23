import { Hono } from 'hono';
import { Env } from '@/types/env';
import { AuthService } from '@/services/authService';
import { createProtectedRoute } from '@/middleware/authFactory';

const verifyRoutes = new Hono<{ Bindings: Env }>()
  .use('*', createProtectedRoute());

// 驗證令牌路由
verifyRoutes.get('/verify', async (c) => {
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

export default verifyRoutes;
