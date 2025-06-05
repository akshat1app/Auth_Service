import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSession, UserSessionSchema } from './schema/user-session.schema';
import { DatabaseModule } from './database/database.module'; 
import { GoogleStrategy } from './strategy/google.strategy';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import {RedisModule} from './redis/redis.module';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

import {Admin,AdminSchema} from './schema/admin-session.schema';
@Module({
  imports: [    
    RedisModule,
    DatabaseModule,
    PassportModule,
    ConfigModule.forRoot(),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'supersecretkey',
      signOptions: { expiresIn: '15m' },
    }),
    MongooseModule.forFeature([{ name: UserSession.name, schema: UserSessionSchema },
      { name: Admin.name, schema: AdminSchema }, ]),
    
  ],
  controllers: [AuthController],
  providers: [AuthService,GoogleStrategy , JwtAuthGuard],       
})
export class AuthModule {}
