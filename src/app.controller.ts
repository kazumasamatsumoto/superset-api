import { Controller, Get, Post, Body, HttpException, HttpStatus, Headers } from '@nestjs/common';
import { AppService } from './app.service';
import * as jwt from 'jsonwebtoken';

interface GuestTokenRequest {
  dashboardId: string;
  username?: string;
}

interface GuestTokenPayload {
  user: {
    username: string;
    first_name: string;
    last_name: string;
  };
  resources: Array<{
    type: string;
    id: string;
  }>;
  rls_rules: Array<{ clause: string }>;
  iat: number;
  exp: number;
  aud: string;
  type: string;
}

// ユーザーとRLSルールのマッピング（完全版）
const USER_RLS_MAPPING: Record<string, string[]> = {
  // 🌍 国別の営業担当者
  'john_usa': ["country = 'USA'"],
  'marie_france': ["country = 'France'"],
  'yuki_japan': ["country = 'Japan'"],
  'hans_germany': ["country = 'Germany'"],
  'sophia_spain': ["country = 'Spain'"],
  
  // 🌏 地域別のマネージャー
  'manager_apac': ["territory = 'APAC'"],
  'manager_emea': ["territory = 'EMEA'"],
  'manager_japan': ["territory = 'Japan'"],
  
  // 🚗 製品ライン別の担当者（全7種類）
  'motorcycles_sales': ["product_line = 'Motorcycles'"],
  'classic_cars_sales': ["product_line = 'Classic Cars'"],
  'trucks_buses_sales': ["product_line = 'Trucks and Buses'"],
  'vintage_cars_sales': ["product_line = 'Vintage Cars'"],
  'planes_sales': ["product_line = 'Planes'"],
  'ships_sales': ["product_line = 'Ships'"],
  'trains_sales': ["product_line = 'Trains'"],
  
  // 💰 取引サイズ別
  'large_deals': ["deal_size = 'Large'"],
  'medium_deals': ["deal_size = 'Medium'"],
  'small_deals': ["deal_size = 'Small'"],
  'small_medium': ["deal_size IN ('Small', 'Medium')"],
  
  // 🔀 複数条件の例（AND条件）
  'japan_motorcycles': ["country = 'Japan'", "product_line = 'Motorcycles'"],
  'usa_large': ["country = 'USA'", "deal_size = 'Large'"],
  'emea_classic_cars': ["territory = 'EMEA'", "product_line = 'Classic Cars'"],
  'france_large': ["country = 'France'", "deal_size = 'Large'"],
  
  // 🚙 複数製品ライン（OR条件）
  'vehicles_only': ["product_line IN ('Motorcycles', 'Classic Cars', 'Vintage Cars', 'Trucks and Buses')"],
  'transport_only': ["product_line IN ('Planes', 'Ships', 'Trains')"],
  
  // 👑 全データ（管理者）
  'admin': [],
};

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Post('api/superset/guest-token')
  generateGuestToken(
    @Body() body: GuestTokenRequest,
    @Headers('x-user-id') userId?: string,
  ) {
    const { dashboardId } = body;
    
    // ユーザー識別（RLS用）
    const username = userId || body.username || 'admin';

    console.log('=== Guest Token Request ===');
    console.log('RLS User:', username);
    console.log('Dashboard ID:', dashboardId);

    // 環境変数チェック
    const secret = process.env.GUEST_TOKEN_JWT_SECRET;
    if (!secret) {
      throw new HttpException(
        'GUEST_TOKEN_JWT_SECRET is not configured',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    // ユーザーに応じたRLSルールを取得
    const rlsRules = this.getRLSRulesForUser(username);
    console.log('RLS Rules:', rlsRules);

    // トークンペイロード作成
    const now = Math.floor(Date.now() / 1000);
    const payload: GuestTokenPayload = {
      user: {
        // Supersetに存在するユーザーを使用
        username: 'guest_user',
        first_name: 'Guest',
        last_name: 'User',
      },
      resources: [
        {
          type: 'dashboard',
          id: dashboardId,
        },
      ],
      rls_rules: rlsRules, // RLS条件で実際のユーザーを識別
      iat: now,
      exp: now + 300, // 5分間有効
      aud: 'superset',
      type: 'guest',
    };

    // JWT生成
    const token = jwt.sign(payload, secret, {
      algorithm: 'HS256',
    });

    // トークンをデコードして確認
    console.log('=== Generated Token ===');
    console.log('Token:', token);
    console.log('Decoded:', jwt.decode(token));

    return { token };
  }

  private getRLSRulesForUser(username: string): Array<{ clause: string }> {
    const rules = USER_RLS_MAPPING[username];
    
    if (!rules) {
      console.warn(`No RLS rules found for user: ${username}, using admin (all data)`);
      return [];
    }
    
    return rules.map(clause => ({ clause }));
  }
}