// src/middleware/authFactory.ts
import { createMiddleware } from 'hono/factory';
import { Env } from '@/types/env';
import { createAuthMiddleware } from '@/middleware/auth';
import { getCookie } from 'hono/cookie';

export const createProtectedRoute = () => {
  return createMiddleware<{ Bindings: Env }>(async (c, next) => {
    try {
      const accessToken = getCookie(c, 'sso_token');

      if (!accessToken) {
        // 檢查是否有 refresh token 可以自動刷新
        const refreshToken = getCookie(c, 'sso_refresh_token');
        if (refreshToken) {
          return c.json({
            error: '訪問令牌已過期',
            needsRefresh: true
          }, 401);
        }
        return c.json({ error: '未授權' }, 401);
      }

      const jwtMiddleware = createAuthMiddleware(c.env.JWT_SECRET || 'dev_secret_123');
      return await jwtMiddleware(c, next);
    } catch (e) {
      // JWT 過期時的處理
      const refreshToken = getCookie(c, 'sso_refresh_token');
      if (refreshToken) {
        return c.json({
          error: '訪問令牌已過期',
          needsRefresh: true
        }, 401);
      }
      return c.json({ error: '未授權' }, 401);
    }
  });
};