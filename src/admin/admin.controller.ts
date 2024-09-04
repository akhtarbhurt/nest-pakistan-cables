import {
  Controller,
  Post,
  Body,
  Param,
  Get,
  Patch,
  Res,
  HttpCode,
  HttpStatus,
  Query,
  Put,
  Req,
} from '@nestjs/common';
import { AdminService } from './admin.service';
import { Response, Request } from 'express';

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Post('create')
  async createAdmin() {
    return await this.adminService.createAdmin();
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async adminLogin(
    @Body('email') email: string,
    @Body('password') password: string,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
    @Body('otp') otp: any,
  ) {
    const deviceInfo = {
      web: req.headers['user-agent'],
      iOS: '',
      android: '',
    };

    const response = await this.adminService.adminLogin(
      email,
      password,
      res,
      req,
      deviceInfo,
      otp,
    );
    return response;
  }

  @Post('login/confirm')
  async confirmAdminLogin(
    @Body('token') token: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    return await this.adminService.confirmAdminLogin(token, res);
  }

  @Put('profile/:adminId')
  async updateAdminProfile(
    @Param('adminId') adminId: string,
    @Body() data: any,
    // @Body('currentUser') currentUser: any,
  ) {
    return await this.adminService.updateAdminProfile(adminId, data);
  }

  @Post('recover')
  async recoverAdminAccount(@Body('email') email: string) {
    return await this.adminService.recoverAdminAccount(email);
  }

  @Post('reset-password')
  async resetAdminPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
    @Body('confirmPassword') confirmPassword: string,
  ) {
    return await this.adminService.resetAdminPassword(
      token,
      newPassword,
      confirmPassword,
    );
  }

  @Post('enable-mfa')
  async enableMFA(@Body('email') email: string) {
    return await this.adminService.enableMFA(email);
  }

  @Post('disable-mfa')
  async disableMFA(@Body('email') email: string) {
    return await this.adminService.disableMFA(email);
  }

  @Post('send-otp')
  async sendOTP(@Body('email') email: string) {
    return await this.adminService.sendOTP(email);
  }
}
