import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateRoleDto } from './dto/CreateRoleDto';
import { UpdatePermissionsDto } from './dto/UpdatePermissionsDto';

@Injectable()
export class RolesService {
  constructor(private prisma: PrismaService) {}

  async createPermission(data: any) {
    return await this.prisma.permissions.create({ data });
  }

  async fetchPermissions() {
    return await this.prisma.permissions.findMany();
  }

  async assignRole(dto: CreateRoleDto, user: any) {
    const existingRole = await this.prisma.role.findFirst({ where: { userId: dto.userId } });

    if (existingRole) {
      throw new BadRequestException('User already has an assigned role.');
    }

    const userExists = await this.prisma.user.findUnique({ where: { id: dto.userId } });
    if (!userExists) {
      throw new NotFoundException('User not found');
    }
    
    const newRole = await this.prisma.role.create({
      data: {
        roleName: dto.roleName,
        assignPermissions: dto.assignPermissions,
        userId: dto.userId,
        status: dto.status,
      },
    });

    return newRole;
  }

  async createRole(roleName: string) {
    return await this.prisma.role.create({
      data: {  roleName : roleName },
    });
  }

  async fetchAllPermissions() {
    const roles = await this.prisma.role.findMany({
      select: {
        roleName: true,
        assignPermissions: true,
        status: true,
      },
    });

    if (!roles.length) {
      throw new NotFoundException('No roles found');
    }

    return roles;
  }

  async updatePermissions(dto: UpdatePermissionsDto, user: any) {
    const permissions = await this.prisma.permissions.findMany();
    const validPermissions = permissions.map(p => p.permission);
    const invalidPermissions = dto?.assignPermissions?.filter((p) => !validPermissions.includes(p));

    if (invalidPermissions?.length) {
      throw new Error(`Invalid permissions: ${invalidPermissions.join(', ')}`);
    }

    const updatedRole = await this.prisma.role.updateMany({
      where: { userId: dto.userId },
      data: {
        assignPermissions: dto.assignPermissions,
        roleName: dto.roleName,
      },
    });

    if (!updatedRole.count) {
      throw new NotFoundException('Role not found for the given userId');
    }

    return updatedRole;
  }

  async deactivatePermissions(userId: string) {
    const updatedRole = await this.prisma.role.updateMany({
      where: { userId },
      data: { status: 'inactive' },
    });

    if (!updatedRole.count) {
      throw new NotFoundException('Role not found for the given userId');
    }

    return updatedRole;
  }

  async searchPermissionByUserId(userId: string) {
    const userRoles = await this.prisma.role.findMany({
      where: { userId },
      select: { assignPermissions: true },
    });

    if (!userRoles.length) {
      throw new NotFoundException('No permissions found for the given userId');
    }

    return userRoles;
  }
}
