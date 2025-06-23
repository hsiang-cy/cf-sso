import { Context } from 'hono';
import { sign, verify } from 'hono/jwt';
import { getCookie, setCookie } from 'hono/cookie';
import { D1Database } from '@cloudflare/workers-types'; // 添加這個導入
import { Env, User } from '../types/env';
import { hashPassword, verifyPassword } from '../tools/crypto';

export class AuthService {
  private db: D1Database;
  private jwtSecret: string;

  constructor(db: D1Database, jwtSecret: string) {
    this.db = db;
    this.jwtSecret = jwtSecret;
  }

  async login(email: string, password: string) {
    const user = await this.db.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(email).first<User>();

    if (!user) {
      throw new Error('用戶不存在');
    }

    const valid = await verifyPassword(password, user.password_hash, user.salt);
    if (!valid) {
      throw new Error('密碼錯誤');
    }

    const payload = {
      sub: user.id,
      exp: Math.floor(Date.now() / 1000) + 86400 // 24小時
    };
    const token = await sign(payload, this.jwtSecret);

    // 保存會話
    await this.db.prepare(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(token, user.id, payload.exp).run();

    return { token, user: { id: user.id, email: user.email } };
  }

  async register(email: string, password: string) {
    const existingUser = await this.db.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();

    if (existingUser) {
      throw new Error('電子郵件已註冊');
    }

    const { hash, salt } = await hashPassword(password);
    const userId = crypto.randomUUID();
    
    await this.db.prepare(
      'INSERT INTO users (id, email, password_hash, salt) VALUES (?, ?, ?, ?)'
    ).bind(userId, email, hash, salt).run();

    return { id: userId, email };
  }

  async verifyToken(c: Context<{ Bindings: Env }>) {
    const token = getCookie(c, 'sso_token');
    if (!token) {
      throw new Error('無效令牌');
    }

    const payload = await verify(token, this.jwtSecret);
    const session = await this.db.prepare(
      'SELECT expires_at FROM sessions WHERE token = ?'
    ).bind(token).first<{ expires_at: number }>();

    if (!session || session.expires_at < Date.now()/1000) {
      throw new Error('會話已過期');
    }

    return {
      valid: true,
      user_id: payload.sub,
      expires: session.expires_at
    };
  }

  async logout(token: string | undefined) {
    if (!token) {
      throw new Error('無效令牌');
    }
    
    await this.db.prepare(
      'DELETE FROM sessions WHERE token = ?'
    ).bind(token).run();
  }

  async getUserInfo(userId: string) {
    const user = await this.db.prepare(
      'SELECT id, email, created_at FROM users WHERE id = ?'
    ).bind(userId).first();

    if (!user) {
      throw new Error('用戶不存在');
    }

    return user;
  }
}