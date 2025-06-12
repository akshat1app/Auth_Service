import { IsEmail, IsString, IsOptional } from 'class-validator';

export class GenerateTokenDto {

    @IsString()
    userId!: string;

    @IsEmail()
    email!: string;

    @IsString()
    role!: string;

    @IsOptional()
    @IsString()
    deviceId?: string;

    @IsOptional()
    @IsString()
    ipAddress?: string;

    @IsOptional()
    @IsString()
    userAgent?: string;

    @IsOptional()
    @IsString()
    fcmToken?:string;
}

    
  