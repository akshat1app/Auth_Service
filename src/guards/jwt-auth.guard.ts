import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
  } from '@nestjs/common';


import { RpcException } from "@nestjs/microservices";
import { AuthService } from '../auth.service';
import { JwtService } from '@nestjs/jwt';

  
  @Injectable()
  export class JwtAuthGuard implements CanActivate {
    constructor(private readonly authService: AuthService,
      private readonly jwtService:JwtService
    ) {}
  
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const rpcContext = context.switchToRpc();
      const data = rpcContext.getData();
       
      const accessToken = data?.accessToken;
     
  
      if (!accessToken) {
        throw new RpcException(
          new UnauthorizedException('Access token is missing'),
        );
      }
  
      const token = accessToken.startsWith('Bearer ')
        ? accessToken.slice(7)
        : accessToken;
  
      try {      
        const decoded = this.jwtService.verify(accessToken, {secret: process.env.JWT_SECRET});
        console.log("decoded",decoded)
  
        data.user = {
          userId: decoded.userId,
          email: decoded.email,
          role: decoded.role,
          issuedAt: decoded.issuedAt,
          expiresAt: decoded.expiresAt,
        };
  
        return true;
      } catch (err) {
        throw new RpcException(
          new UnauthorizedException('Invalid or expired token'),
        );
      }
    }
  }
  