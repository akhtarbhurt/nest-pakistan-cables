// src/user-management/user-management.controller.ts
import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  Res,
  HttpCode,
  Put,
  Patch,
  HttpStatus,
  SetMetadata,
  UseGuards,
} from '@nestjs/common';
import { UserManagementService } from './user-management.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Response } from 'express';
import { RolesGuard } from 'src/middleware/roleGuard.middleware';

@Controller('user')
export class UserManagementController {
  constructor(private readonly userManagementService: UserManagementService) {}

  @Post('create')
  @SetMetadata('roles', ['superadmin'])
  @UseGuards(RolesGuard)
  async createUser(@Body() createUserDto: CreateUserDto) {
    return this.userManagementService.createUser(createUserDto);
  }

  @Get('all')
  @SetMetadata('roles', ['superadmin'])
  @UseGuards(RolesGuard)
  async fetchAllUser() {
    return this.userManagementService.fetchAllUser();
  }

  @Post('login')
  @HttpCode(200)
  async loginUser(@Body() loginUserDto: LoginUserDto, @Res() res: any) {
    const { token, message } = await this.userManagementService.loginUser(
      loginUserDto,
      res,
    );
    res.cookie('accessToken', token, { httpOnly: true, secure: false });
    return res.json({ token, message });
  }

  @Put('update/:userId')
  @SetMetadata('roles', ['superadmin'])
  @UseGuards(RolesGuard)
  async updateUser(
    @Body() updateUserDto: UpdateUserDto,
    @Param('userId') userId: string,
  ) {
    return this.userManagementService.updateUser(updateUserDto, userId);
  }

  @Patch('deactivate/:userId')
  @SetMetadata('roles', ['superadmin'])
  @UseGuards(RolesGuard)
  async deactivateUser(@Param('userId') userId: string) {
    return this.userManagementService.deactivateUser(userId);
  }

  @Get(':userId')
  @SetMetadata('roles', ['superadmin'])
  @UseGuards(RolesGuard)
  async getUserById(@Param('userId') userId: string) {
    return this.userManagementService.getUserById(userId);
  }

  @Post('logout')
  @HttpCode(200)
  async logoutUser(@Res() res: Response) {
    await this.userManagementService.logoutUser(res);
    res.status(HttpStatus.OK).json({ message: 'logout successfull' });
  }

  @Post('request-password-reset')
  async requestPasswordReset(
    @Body() requestPasswordResetDto: RequestPasswordResetDto,
  ) {
    return this.userManagementService.requestPasswordReset(
      requestPasswordResetDto,
    );
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.userManagementService.resetPassword(resetPasswordDto);
  }
}
