import {
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
  } from '@nestjs/common';
  import { Reflector } from '@nestjs/core';
  import { JwtService } from '@nestjs/jwt';
  
  @Injectable()
  export class RolesGuard implements CanActivate {
    constructor(
      private readonly reflector: Reflector,
      private readonly jwtService: JwtService,
    ) {}
  
    canActivate(context: ExecutionContext): boolean {
      const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
      if (!requiredRoles) {
        return true;
      }
  
      const request = context.switchToHttp().getRequest();
      const token = request.cookies['accessToken'];
  
      if (!token) {
        throw new UnauthorizedException('Token is missing');
      }
  
      try {
        const decoded = this.jwtService.verify(token, {
          secret: process.env.ACCESS_TOKEN_SECRET,
        });
  
        const userRole = decoded.role;
        const hasAccess = requiredRoles.includes(userRole);
  
        if (!hasAccess) {
          throw new UnauthorizedException('You do not have access to this route');
        }
  
        request.user = { userId: decoded.userId, roles: [userRole] };
        return true;
      } catch (error) {
        throw new UnauthorizedException('Invalid or expired token');
      }
    }
  }
  