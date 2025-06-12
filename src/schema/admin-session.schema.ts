import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class Admin extends Document {
  @Prop({ required: true, type: String })
  adminId?:string;


  @Prop({ required: true, unique: true })
  email!: string;

  // @Prop({ required: true })
  // password!: string;

  @Prop({ default: 'admin' })
  role!: string;

  @Prop()
  name?: string;

  @Prop()
  deviceId?: string; 

    @Prop()
    ipAddress?: string;
  

  @Prop()
  fcmToken?: string;
}

export const AdminSchema = SchemaFactory.createForClass(Admin);

