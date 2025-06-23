// src/routes/auth/index.ts
import { Hono } from 'hono';
import { Env } from '@/types/env';
import publicAuth from './public';
import protectedAuth from './protected';
import profileAuth from './profile';
import refreshAuth from './refresh'; // 新增

const auth = new Hono<{ Bindings: Env }>();

// 合併所有認證相關路由
auth.route('/', publicAuth);      // /auth/login, /auth/register
auth.route('/', protectedAuth);   // /auth/verify, /auth/logout
auth.route('/', profileAuth);     // /auth/me
auth.route('/', refreshAuth);     // /auth/refresh

export default auth;