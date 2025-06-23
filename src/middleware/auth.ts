import { Context, Next } from 'hono';
import { jwt } from 'hono/jwt';
import { Env } from '../types/env';

export const createAuthMiddleware = (jwtSecret: string) => {
  return jwt({
    secret: jwtSecret,
    cookie: 'sso_token',
  });
};

export const authMiddleware = async (c: Context<{ Bindings: Env }>, next: Next) => {
  // 跳過不需要驗證的路由
  if (c.req.path === '/login' || c.req.path === '/register' || c.req.path === '/dev-test') {
    return await next();
  }

  try {
    const jwtMiddleware = createAuthMiddleware(c.env.JWT_SECRET || 'dev_secret_123');
    return await jwtMiddleware(c, next);
  } catch (e) {
    return c.json({ error: '未授權' }, 401);
  }
};