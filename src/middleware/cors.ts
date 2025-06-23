import { Context, Next } from 'hono';

export const corsMiddleware = async (c: Context, next: Next) => {
  const allowedOrigins = [
    'https://your-pages-domain.pages.dev',// 前端域名
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ];
  
  const origin = c.req.header('Origin');
  
  if (origin && allowedOrigins.includes(origin)) {
    c.header('Access-Control-Allow-Origin', origin);
  }
  
  c.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS,DELETE');
  c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  c.header('Access-Control-Allow-Credentials', 'true');

  if (c.req.method === 'OPTIONS') {
    return new Response('', { status: 204 });
  }

  await next();
};