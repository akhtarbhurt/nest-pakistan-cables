import { Controller, Get, Post, Body, Param, Patch, Delete, Req } from '@nestjs/common';
import { RolesService } from './roles.service';
import { CreateRoleDto } from './dto/CreateRoleDto';
import { UpdatePermissionsDto } from './dto/UpdatePermissionsDto';

@Controller('roles')
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Post('assign-roles')
  createRole(@Body() dto: CreateRoleDto, @Req() req) {
    return this.rolesService.assignRole(dto, req.user);
  }

  @Post('create-role')
  createRoleWithOnlyName(@Body('roleName') roleName: string) {
    return this.rolesService.createRole(roleName);
  }

  @Get('view-roles')
  fetchAllPermissions() {
    return this.rolesService.fetchAllPermissions();
  }

  @Patch('update-permissions')
  updatePermissions(@Body() dto: UpdatePermissionsDto, @Req() req) {
    return this.rolesService.updatePermissions(dto, req.user);
  }

  @Patch('deactivate/:userId')
  deactivatePermissions(@Param('userId') userId: string) {
    return this.rolesService.deactivatePermissions(userId);
  }

  @Get('search-permissions/:userId')
  searchPermissionByUserId(@Param('userId') userId: string) {
    return this.rolesService.searchPermissionByUserId(userId);
  }

  @Post('create-permission')
  createPermission(@Body() data: any) {
    return this.rolesService.createPermission(data);
  }

  @Get('view-permission')
  fetchPermissions() {
    return this.rolesService.fetchPermissions();
  }
}
