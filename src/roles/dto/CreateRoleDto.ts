import { IsUUID, IsString, IsOptional, IsArray } from 'class-validator';

export class CreateRoleDto {
  @IsString()
  roleName: string;

  @IsArray()
  assignPermissions: string[];

  @IsUUID()
  userId: string;

  @IsOptional()
  @IsString()
  status?: string;
}
