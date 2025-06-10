import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document, Types } from 'mongoose';

@Schema({ timestamps: true })
export class UserSession extends Document {
  @Prop({ type:String ,required: true })
  userId?: string;
 

  @Prop({ required: true })
  refreshToken?: string;

  @Prop()
  deviceId?: string; 
  
  @Prop({ default: 'active' }) 
  status!: string;

  @Prop()
  ipAddress?: string;

  @Prop()
  userAgent?: string;
}

export const UserSessionSchema = SchemaFactory.createForClass(UserSession);