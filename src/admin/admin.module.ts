import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  controllers: [AdminController],
  providers: [AdminService],
  imports: [PrismaModule, JwtModule.register({
    secret: process.env.ACCESS_TOKEN_SECRET, 
    signOptions: { expiresIn: '1d' },
  }),]
})
export class AdminModule {}
