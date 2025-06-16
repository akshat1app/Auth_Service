import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class AdminSession extends Document {
  @Prop({ type:String ,required: true })
  adminId?: string;
 

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
  
  @Prop()
  fcmToken?: string;
}

export const AdminSchema = SchemaFactory.createForClass(AdminSession);

