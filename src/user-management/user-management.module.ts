import { Module } from '@nestjs/common';
import { UserManagementController } from './user-management.controller';
import { UserManagementService } from './user-management.service';
import { JwtModule } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.ACCESS_TOKEN_SECRET, 
      signOptions: { expiresIn: '1d' },
    }),
  ],
  providers: [UserManagementService, PrismaService],
  exports: [UserManagementService],
  controllers: [UserManagementController]
})
export class UserManagementModule {}
