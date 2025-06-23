import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { verify } from 'hono/jwt';
import { Env } from '../types/env';
import { createAuthMiddleware } from '../middleware/auth';

const user = new Hono<{ Bindings: Env }>()
  .use('*', async (c, next) => {
    try {
      const jwtMiddleware = createAuthMiddleware(c.env.JWT_SECRET || 'dev_secret_123');
      return await jwtMiddleware(c, next);
    } catch (e) {
      return c.json({ error: '未授權' }, 401);
    }
  });

// 受保護的路由
user.get('/protected', async (c) => {
  try {
    const token = getCookie(c, 'sso_token');
    if (!token) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const payload = await verify(token, c.env.JWT_SECRET || 'dev_secret_123');
    return c.json({ message: 'Authenticated!', user_id: payload.sub });
  } catch (e) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
});

export default user;