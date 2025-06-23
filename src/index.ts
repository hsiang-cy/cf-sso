import { Hono } from 'hono';
import { Env } from './types/env';
import { authMiddleware } from './middleware/auth';
import { corsMiddleware } from './middleware/cors';
import authRoutes from './routes/auth';
import userRoutes from './routes/user';

const app = new Hono<{ Bindings: Env }>();

// 全域中間件
app.use('*', corsMiddleware);
// app.use('/*', authMiddleware);

// 路由
app.route('/auth', authRoutes);
app.route('/api', userRoutes);

// 開發測試路由
app.get('/dev-test', (c) => c.text('SSO Local Dev Ready'));

export default app;