import { Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Model, Types } from "mongoose";
import { UserSession } from "./schema/user-session.schema";
import { InjectModel } from "@nestjs/mongoose";
import { OAuth2Client } from 'google-auth-library';
import { RedisService } from "./redis/redis.service";
import { RpcException } from "@nestjs/microservices";
import { AdminSession } from "./schema/admin-session.schema";
import { v4 as uuidv4 } from 'uuid';
import { status } from '@grpc/grpc-js';



interface ValidateTokenResponse {
  userId: string;
  email: string;
  role: string;
  issuedAt: number;
  expiresAt: number;
}

@Injectable()
export class AuthService {
  private oauth2Client: OAuth2Client;
  constructor(
    private jwtService: JwtService,
    private readonly redisService: RedisService,
    @InjectModel(UserSession.name) private sessionModel: Model<UserSession>,
    @InjectModel(AdminSession.name) private AdminSessionModel: Model<AdminSession>
  ) {
    this.oauth2Client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  }

  async generateToken(payload: {
    userId: string;
    email: string;
    role: string;
    deviceId?: string;
    ipAddress?: string;
    userAgent?: string;
    fcmToken?: string;

  }) {
    try {
      console.log(payload)
      const access_token = this.jwtService.sign(payload, {
        expiresIn: "1d",
        subject: payload.userId,
      });

      const refresh_token = this.jwtService.sign(payload, {
        expiresIn: "7d",
        subject: payload.userId,

      });
      console.log(access_token, refresh_token);

      if (payload.role == 'user') {
        const alreadyLoggedIn = await this.sessionModel.find({userId: payload.userId, deviceId: payload.deviceId, status:'active'})
        if(!alreadyLoggedIn){
          await this.sessionModel.create({
            refreshToken: refresh_token,
            userId: payload.userId,
            deviceId: payload.deviceId,
            status: 'active',
            fcmToken: payload.fcmToken,
          });
        }
        

        await this.redisService.set(
          `access_token:${payload.role}:${payload.userId}:${payload.deviceId}`,
          access_token,
          24*60*60*1000,
        );
      }
      else if (payload.role == 'admin') {
        const alreadyLoggedIn = await this.AdminSessionModel.find({ userId: payload.userId, deviceId: payload.deviceId, status: 'active' })
        if (!alreadyLoggedIn) {
          await this.AdminSessionModel.create({
            refreshToken: refresh_token,
            adminId: payload.userId,
            deviceId: payload.deviceId,
            status: 'active',
            fcmToken: payload.fcmToken,

          });
        }


        await this.redisService.set(
          `access_token:${payload.role}:${payload.userId}:${payload.deviceId}`,
          access_token,
          24*60*60*1000,
        );
      }

      const response = { access_token, refresh_token };
      console.log(response)
      return response;
    } catch (err) {
      console.error('[GenerateToken] Internal Error:', err);
      throw err;
    }
  }



  async validateToken(request: { access_token: string }): Promise<ValidateTokenResponse> {
    try {
      console.log('Validating token:', request.access_token);


      const token = request.access_token.startsWith('Bearer ') ? request.access_token.slice(7) : request.access_token;

      const decoded = this.jwtService.verify(token, { secret: process.env.JWT_SECRET });
      console.log('Token decoded successfully:', decoded);
      console.log('Decoded token payload:', {
        userId: decoded.userId,
        deviceId: decoded.deviceId,
        email: decoded.email,
        role: decoded.role
      });

      const userId = decoded.userId;
      const deviceId = decoded.deviceId;

      if (!userId || !deviceId) {
        console.error('Token validation failed: Missing userId or deviceId', { userId, deviceId });
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Missing userId or deviceId in token'
        });
      }

      const redisKey = `access_token:${decoded.role}:${userId}:${deviceId}`;
      const storedToken = await this.redisService.get(redisKey);

      if (!storedToken) {
        console.error('Token not found in Redis. Possibly expired or logged out.', { redisKey });
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Access token not active or expired (Redis)',
        });
      }

      if (storedToken !== token) {
        console.error('Access token mismatch in Redis', { expected: storedToken, got: token });
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Access token mismatch',
        });
      }



      const session = await this.sessionModel.findOne({
        userId,
        deviceId,
        status: 'active',



      });

      console.log('Found session:', session);

      if (!session) {
        console.error('Token validation failed: No active session found', { userId, deviceId });
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Session inactive or device mismatch'
        });
      }

      return {
        userId,
        email: decoded.email,
        role: decoded.role,
        issuedAt: decoded.iat,
        expiresAt: decoded.exp
      };
    } catch (err) {
      console.error('Token validation failed:', err);
      if (err instanceof RpcException) {
        throw err;
      }
      throw new RpcException({
        code: status.UNAUTHENTICATED,
        message: 'Invalid or expired token'
      });
    }
  }





  async saveUserSession(userId: string, refreshToken: string, deviceId: string, fcmToken?: string) {
    const session = new this.sessionModel({
      userId,
      refreshToken,
      deviceId,
      status: 'active',
      fcmToken,
    });

    await session.save();
  }

  async regenerateAccessToken({
    userId,
    deviceId,
    refreshToken,
  }: {
    userId: string;
    deviceId: string;
    refreshToken: string;
  }): Promise<{ access_token: string }> {
    try {
      const session = await this.sessionModel.findOne({
        userId,
        deviceId,
        refreshToken,
      });

      if (!session) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      const decoded = this.jwtService.verify(refreshToken);

      const newAccessToken = this.jwtService.sign(
        {
          userId,
          email: decoded.email,
          role: decoded.role,
          deviceId,
        },
        {
          expiresIn: '1d',
          subject: userId,
        }
      );

      await this.redisService.set(
        `access_token:${userId}:${deviceId}`,
        newAccessToken,
        24*60*60*1000 
      );

      return { access_token: newAccessToken };
    } catch (err) {
      console.error('[regenerateAccessToken] Error:', err);
      throw new UnauthorizedException('Token regeneration failed');
    }
  }

  async googleSignup(googleToken: string, deviceId: string) {
    const ticket = await this.oauth2Client.verifyIdToken({
      idToken: googleToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();


    if (!payload) {
      throw new Error('Failed to verify Google token: Payload is undefined');
    }


    const userId = payload.sub;
    const email = payload.email;
    const name = payload.name;


    if (!userId || !email || !name) {
      throw new Error('Missing required user information in Google token payload');
    }


    const tokens = await this.generateToken({ userId, email, role: 'user' });


    await this.saveUserSession(userId, tokens.refresh_token, deviceId);

    return {
      ...tokens,
      email,
      name,
    };

  }

  async logout(userId: string, deviceId: string) {
    try {

      await this.redisService.del(`access_token:${userId}:${deviceId}`);


      const session = await this.sessionModel.findOneAndUpdate(
        { userId, deviceId, status: 'active' },
        { status: 'inactive' },
        { new: true }
      );

      if (!session) {
        throw new RpcException({
          code: 16,
          message: 'Session not found or already inactive',
        });
      }

      return { message: 'Logout successful' };
    } catch (error) {
      console.error('[AuthService Logout Error]', error);
      throw new RpcException({
        code: 13,
        message: 'Logout failed',
      });
    }
  }

}