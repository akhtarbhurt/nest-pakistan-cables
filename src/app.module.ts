import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { UserManagementModule } from './user-management/user-management.module';
import { JwtModule } from '@nestjs/jwt';
import { AdminModule } from './admin/admin.module';
import { TeamManagementModule } from './team-management/team-management.module';
import { PrismaModule } from './prisma/prisma.module';
import { APP_GUARD } from '@nestjs/core';
import { RolesGuard } from './middleware/roleGuard.middleware';
import { RolesController } from './roles/roles.controller';
import { RolesService } from './roles/roles.service';
import { RolesModule } from './roles/roles.module';

@Module({
  imports: [
    UserManagementModule,
    AdminModule,
    TeamManagementModule,
    PrismaModule,
    RolesModule,
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.register({
      secret: process.env.ACCESS_TOKEN_SECRET,
      signOptions: { expiresIn: '1d' },
    }),
    RolesModule,
  ],
  controllers: [AppController, RolesController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    RolesService,
  ],
})
export class AppModule {}
