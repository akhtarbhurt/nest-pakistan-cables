import { Module } from '@nestjs/common';
import { TeamManagementController } from './team-management.controller';
import { TeamManagementService } from './team-management.service';
import { JwtModule } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.ACCESS_TOKEN_SECRET, 
      signOptions: { expiresIn: '1d' },
    }),
  ],
  providers: [TeamManagementService, PrismaService],
  exports: [TeamManagementService],
  controllers: [TeamManagementController]
})
export class TeamManagementModule {}
