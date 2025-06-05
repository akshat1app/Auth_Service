import { UseGuards, Controller, Get, Req  } from '@nestjs/common';
import { GrpcMethod, RpcException } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { GenerateTokenDto } from './dto/generate-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ValidateTokenDto } from './dto/validate-token.dto';

@Controller()
export class AuthController {
  constructor(private authService: AuthService) {}
  

  @GrpcMethod('AuthService', 'GenerateToken')
  async generateToken(data: GenerateTokenDto) {
    const result = await this.authService.generateToken(data);
    return {
      access_token: result.access_token,
      refresh_token: result.refresh_token,
    };
  }

  @UseGuards(JwtAuthGuard)
  @GrpcMethod('AuthService', 'ValidateToken')
  validateToken(data: { accessToken?: string }) {
     const accessToken=data.accessToken;
  if (!accessToken) {
    throw new RpcException('Access token is missing');
  }

  return this.authService.validateToken( accessToken );
}


  @GrpcMethod('AuthService', 'Logout')
async logout(data: { userId: string , deviceId: string}) {
  return this.authService.logout(data.userId, data.deviceId);
}


  @GrpcMethod('AuthService', 'GoogleSignup')
  async googleSignup(data:{googleToken:string, deviceId:string}) {
    const user = await this.authService.googleSignup(data.googleToken, data.deviceId);
    return {
      access_token: user.access_token,
      refresh_token: user.refresh_token,
      email: user.email,
      name: user.name,
    };
  }
  @GrpcMethod('AuthService', 'RegenerateAccessToken')
  async regenerateAccessToken(data: { userId: string; refreshToken: string; deviceId?: string }) {
    const { userId, refreshToken, deviceId } = data;
    if (!userId || !refreshToken) {
      throw new RpcException('Missing userId or refreshToken');
    }
    const accessToken = await this.authService.regenerateAccessToken({ 
      userId, 
      refreshToken, 
      deviceId: deviceId ?? ''  // ensure string type
    });
    return { access_token: accessToken };
  }
  
}
