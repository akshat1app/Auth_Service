// import { Module, Global } from '@nestjs/common';
// import { RedisModule as NestRedisModule } from '@nestjs-modules/ioredis';
// import { RedisService } from './redis.service';

// @Global()
// @Module({
//   imports: [
//     NestRedisModule.forRoot({
//       config: {
//         host: process.env.REDIS_HOST || 'localhost',
//         port: parseInt(process.env.REDIS_PORT) || 6379,
//       },
//     }),
//   ],
//   providers: [RedisService],
//   exports: [RedisService],
// })
// export class RedisModule {}
import { Module, Global } from '@nestjs/common';
import { RedisService } from './redis.service';

@Global()
@Module({
  providers: [RedisService],
  exports: [RedisService],
})
export class RedisModule {}

