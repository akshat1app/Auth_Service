import { NestFactory } from '@nestjs/core';
import { AuthModule } from './auth.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import mongoose from 'mongoose';
import * as dotenv from 'dotenv';
dotenv.config();


async function bootstrap() {
  try {
    await mongoose.connect(process.env.MONGO_URI as string);
    //console.log(`Connected to MongoDB: ${process.env.MONGO_URI}`);

    const grpcApp = await NestFactory.createMicroservice<MicroserviceOptions>(AuthModule, {
      transport: Transport.GRPC,
      options: {
        package: 'auth', 
        protoPath: join(__dirname, '../src/proto/auth.proto'), 
        url: 'localhost:50052',
        loader: {
          keepCase: true,
        },
      },
    });

    await grpcApp.listen();

    const httpApp = await NestFactory.create(AuthModule);
    await httpApp.listen(3001);
    console.log('Auth HTTP server is running on http://localhost:3001');

  } catch (err) {
    console.error('Failed to start Auth Service:', err);
    process.exit(1);
  }
}

bootstrap();
