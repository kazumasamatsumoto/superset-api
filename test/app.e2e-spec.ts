import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { AuthService } from './../src/auth/auth.service';
import * as jwt from 'jsonwebtoken';

describe('AppController (e2e)', () => {
  let app: INestApplication<App>;
  let authService: AuthService;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    authService = moduleFixture.get<AuthService>(AuthService);
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('GET /', () => {
    it('should return "Hello World!"', () => {
      return request(app.getHttpServer())
        .get('/')
        .expect(200)
        .expect('Hello World!');
    });
  });

  describe('POST /api/auth/login', () => {
    it('should return access token on successful login', async () => {
      // AuthServiceをモック
      jest.spyOn(authService, 'getAccessToken').mockResolvedValue('mock-access-token');

      const response = await request(app.getHttpServer())
        .post('/api/auth/login')
        .expect(201);

      expect(response.body).toHaveProperty('access_token');
      expect(response.body.access_token).toBe('mock-access-token');
      expect(response.body.token_type).toBe('Bearer');
    });
  });

  describe('POST /api/superset/guest-token', () => {
    const mockSecret = 'test-secret-key';
    const mockAccessToken = 'valid-access-token';

    beforeEach(() => {
      process.env.GUEST_TOKEN_JWT_SECRET = mockSecret;
      // validateAccessTokenをモック
      jest.spyOn(authService, 'validateAccessToken').mockResolvedValue(true);
    });

    afterEach(() => {
      delete process.env.GUEST_TOKEN_JWT_SECRET;
      jest.restoreAllMocks();
    });

    it('should return 401 without authorization header', async () => {
      await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .send({
          dashboardId: 'test-dashboard-id',
          username: 'admin',
        })
        .expect(401);
    });

    it('should generate guest token for admin user with valid access token', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .set('Authorization', `Bearer ${mockAccessToken}`)
        .send({
          dashboardId: 'test-dashboard-id',
          username: 'admin',
        })
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(typeof response.body.token).toBe('string');

      // トークンをデコードして検証
      const decoded = jwt.decode(response.body.token) as any;
      expect(decoded.user.username).toBe('admin');
      expect(decoded.resources[0].id).toBe('test-dashboard-id');
      expect(decoded.rls_rules).toEqual([]);
    });

    it('should generate guest token with RLS rules for specific user', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .set('Authorization', `Bearer ${mockAccessToken}`)
        .send({
          dashboardId: 'dashboard-123',
          username: 'john_usa',
        })
        .expect(201);

      expect(response.body).toHaveProperty('token');

      const decoded = jwt.decode(response.body.token) as any;
      expect(decoded.user.username).toBe('john_usa');
      expect(decoded.rls_rules).toEqual([{ clause: "country = 'USA'" }]);
    });

    it('should use x-user-id header if provided', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .set('Authorization', `Bearer ${mockAccessToken}`)
        .set('x-user-id', 'marie_france')
        .send({
          dashboardId: 'dashboard-456',
        })
        .expect(201);

      const decoded = jwt.decode(response.body.token) as any;
      expect(decoded.user.username).toBe('marie_france');
      expect(decoded.rls_rules).toEqual([{ clause: "country = 'France'" }]);
    });

    it('should handle multiple RLS rules', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .set('Authorization', `Bearer ${mockAccessToken}`)
        .send({
          dashboardId: 'dashboard-789',
          username: 'japan_motorcycles',
        })
        .expect(201);

      const decoded = jwt.decode(response.body.token) as any;
      expect(decoded.rls_rules).toEqual([
        { clause: "country = 'Japan'" },
        { clause: "product_line = 'Motorcycles'" },
      ]);
    });

    it('should return 500 if JWT secret is not configured', async () => {
      delete process.env.GUEST_TOKEN_JWT_SECRET;

      await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .set('Authorization', `Bearer ${mockAccessToken}`)
        .send({
          dashboardId: 'test-dashboard',
          username: 'admin',
        })
        .expect(500);
    });

    it('should default to admin if no username provided', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .set('Authorization', `Bearer ${mockAccessToken}`)
        .send({
          dashboardId: 'dashboard-default',
        })
        .expect(201);

      const decoded = jwt.decode(response.body.token) as any;
      expect(decoded.user.username).toBe('admin');
    });

    it('should return 401 with invalid access token', async () => {
      jest.spyOn(authService, 'validateAccessToken').mockResolvedValue(false);

      await request(app.getHttpServer())
        .post('/api/superset/guest-token')
        .set('Authorization', 'Bearer invalid-token')
        .send({
          dashboardId: 'test-dashboard',
          username: 'admin',
        })
        .expect(401);
    });
  });
});
