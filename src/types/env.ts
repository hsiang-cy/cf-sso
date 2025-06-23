import { D1Database } from '@cloudflare/workers-types';

export type Env = {
  DB: D1Database;
  JWT_SECRET: string;
}

export interface User {
  id: string;
  email: string;
  password_hash: string;
  salt: string;
  created_at: number;
}

export interface Session {
  token: string;
  user_id: string;
  expires_at: number;
}