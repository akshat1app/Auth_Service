
import { IsString } from 'class-validator';

export class ValidateTokenDto {
  @IsString()
  accessToken?: string;
}
