import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';

export interface CustomRequest extends Request {
  user?: {
    userId: string;
    roles: string[];
  };
}

@Injectable()
export class RoleMiddleware implements NestMiddleware {
  constructor(
    private readonly jwtService: JwtService,
    private readonly reflector: Reflector,
  ) {}

  use(req: CustomRequest, res: Response, next: NextFunction) {
    const token = req.cookies['accessToken'];

    if (!token) {
      console.error('Token is missing in cookies');
      throw new UnauthorizedException('Token is missing');
    }

    try {
      const decoded = this.jwtService.verify(token, {
        secret: process.env.ACCESS_TOKEN_SECRET,
      });

      console.log('decoded', decoded);

      // Extract roles from metadata
      const requiredRoles = this.reflector.get<string[]>('roles', req.route) || [];

      console.log('requiredRoles:', requiredRoles);

      const userRole = decoded.role;

      console.log('userRole:', userRole);

      // Check if the user's role matches any of the required roles
      const hasAccess = requiredRoles.includes(userRole);

      console.log('hasAccess:', hasAccess);

      if (!hasAccess) {
        console.error('User does not have access to this route');
        throw new UnauthorizedException('You do not have access to this route');
      }

      req.user = { userId: decoded.userId, roles: [userRole] };

      next();
    } catch (error) {
      console.error('Error verifying token:', error.message);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}

