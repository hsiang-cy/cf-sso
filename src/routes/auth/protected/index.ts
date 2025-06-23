import { Hono } from 'hono';
import { Env } from '@/types/env';
import verifyRoutes from './verify';
import logoutRoutes from './logout';
import { createProtectedRoute } from '@/middleware/authFactory';


const protectedAuth = new Hono<{ Bindings: Env }>();
protectedAuth.use('*', createProtectedRoute());

// 組合受保護的路由
protectedAuth.route('/', verifyRoutes);   // /auth/verify
protectedAuth.route('/', logoutRoutes);   // /auth/logout

export default protectedAuth;
