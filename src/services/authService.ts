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

  // src/services/authService.ts
  async login(email: string, password: string) {
    const user = await this.db.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(email).first<User>();

    if (!user) {
      throw new Error('用戶不存在');
    }

    // 驗證密碼
    const valid = await verifyPassword(password, user.password_hash, user.salt);
    if (!valid) {
      throw new Error('密碼錯誤');
    }

    // 生成 Access Token (短期)
    const accessPayload = {
      sub: user.id,
      type: 'access',
      exp: Math.floor(Date.now() / 1000) + 900 // 15分鐘
    };

    // 生成 Refresh Token (長期)
    const refreshPayload = {
      sub: user.id,
      type: 'refresh',
      exp: Math.floor(Date.now() / 1000) + 604800 // 7天
    };

    // 實際簽發 tokens
    const accessToken = await sign(accessPayload, this.jwtSecret);
    const refreshToken = await sign(refreshPayload, this.jwtSecret);

    // 儲存 refresh token 到數據庫
    await this.db.prepare(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(refreshToken, user.id, refreshPayload.exp).run();

    return {
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email }
    };
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

    try {
      const payload = await verify(token, this.jwtSecret);

      // 檢查 token 類型
      if (payload.type !== 'access') {
        throw new Error('無效的令牌類型');
      }

      return {
        valid: true,
        user_id: payload.sub,
        expires: payload.exp
      };
    } catch (error) {
      throw new Error('令牌驗證失敗');
    }
  }

  async logout(refreshToken: string | undefined) {
    if (!refreshToken) {
      return; // 沒有 refresh token 也算成功登出
    }

    await this.db.prepare(
      'DELETE FROM sessions WHERE token = ?'
    ).bind(refreshToken).run();
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

  async refreshAccessToken(refreshToken: string) {
    try {
      // 驗證 refresh token
      const payload = await verify(refreshToken, this.jwtSecret);

      if (payload.type !== 'refresh') {
        throw new Error('無效的刷新令牌類型');
      }

      // 檢查 refresh token 是否在數據庫中存在且有效
      const session = await this.db.prepare(
        'SELECT expires_at FROM sessions WHERE token = ? AND user_id = ?'
      ).bind(refreshToken, payload.sub).first<{ expires_at: number }>();

      if (!session || session.expires_at < Date.now() / 1000) {
        throw new Error('刷新令牌已過期或無效');
      }

      // 生成新的 access token
      const newAccessPayload = {
        sub: payload.sub,
        type: 'access',
        exp: Math.floor(Date.now() / 1000) + 900 // 15分鐘
      };

      const newAccessToken = await sign(newAccessPayload, this.jwtSecret);

      return { accessToken: newAccessToken };
    } catch (error) {
      throw new Error('刷新令牌失敗');
    }
  }
}