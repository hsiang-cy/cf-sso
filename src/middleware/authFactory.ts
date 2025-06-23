import { createMiddleware } from 'hono/factory';
import { Env } from '@/types/env';
import { createAuthMiddleware } from '@/middleware/auth';

export const createProtectedRoute = () => {
  return createMiddleware<{ Bindings: Env }>(async (c, next) => {
    try {
      const jwtMiddleware = createAuthMiddleware(c.env.JWT_SECRET || 'dev_secret_123');
      return await jwtMiddleware(c, next);
    } catch (e) {
      return c.json({ error: '未授權' }, 401);
    }
  });
};
