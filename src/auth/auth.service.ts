import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import axios from 'axios';

interface LoginResponse {
  access_token: string;
  refresh_token?: string;
}

@Injectable()
export class AuthService {
  private readonly supersetUrl: string;
  private readonly username: string;
  private readonly password: string;

  constructor() {
    this.supersetUrl = process.env.SUPERSET_URL || 'http://localhost:8088';
    this.username = process.env.SUPERSET_USERNAME || '';
    this.password = process.env.SUPERSET_PASSWORD || '';

    if (!this.username || !this.password) {
      console.warn('SUPERSET_USERNAME or SUPERSET_PASSWORD not configured');
    }
  }

  /**
   * Supersetからアクセストークンを取得
   */
  async getAccessToken(): Promise<string> {
    if (!this.username || !this.password) {
      throw new HttpException(
        'Superset credentials not configured',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    try {
      const response = await axios.post<LoginResponse>(
        `${this.supersetUrl}/api/v1/security/login`,
        {
          username: this.username,
          password: this.password,
          provider: 'db',
          refresh: true,
        },
      );

      if (!response.data.access_token) {
        throw new HttpException(
          'Failed to retrieve access token from Superset',
          HttpStatus.UNAUTHORIZED,
        );
      }

      console.log('✅ Successfully obtained Superset access token');
      return response.data.access_token;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        console.error('Superset login failed:', error.response?.data || error.message);
        throw new HttpException(
          `Superset authentication failed: ${error.response?.data?.message || error.message}`,
          error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }
      throw error;
    }
  }

  /**
   * アクセストークンの検証
   */
  async validateAccessToken(token: string): Promise<boolean> {
    try {
      // Supersetの /api/v1/me/ エンドポイントでトークンを検証（末尾のスラッシュ必須）
      const response = await axios.get(`${this.supersetUrl}/api/v1/me/`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      return response.status === 200;
    } catch (error) {
      console.error('Token validation failed:', error);
      return false;
    }
  }
}
