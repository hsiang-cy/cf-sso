import { Hono } from 'hono';
import { Env } from '@/types/env';
import publicAuth from './public';
import protectedAuth from './protected';
import profileAuth from './profile';

const auth = new Hono<{ Bindings: Env }>();

// 合併所有認證相關路由
auth.route('/', publicAuth);      // /auth/login, /auth/register
auth.route('/', protectedAuth);   // /auth/verify, /auth/logout
auth.route('/', profileAuth);     // /auth/me

export default auth;
