import { Context, Next } from 'hono';

export const corsMiddleware = async (c: Context, next: Next) => {
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (c.req.method === 'OPTIONS') {
    return new Response('', { status: 204 });
  }

  await next();
};