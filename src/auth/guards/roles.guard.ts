import { CanActivate, ExecutionContext, Injectable, ForbiddenException, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Reflector } from '@nestjs/core';
import { Repository } from 'typeorm';
import { Auth } from '../entities/auth.entity';  // Assuming this is the entity for users
import { JwtService } from '@nestjs/jwt';        // JWT service to decode the token
import { Roles } from '../enums/role.enums';     // Assuming this is the enum for roles
import { Response } from 'express';             // To redirect the user on error

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @InjectRepository(Auth) private authRepo: Repository<Auth>,  // Injecting the Auth repository
    private jwtService: JwtService  // Injecting the JwtService to decode the JWT token
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Retrieve the roles metadata applied to the route handler
    const requiredRoles = this.reflector.get<Roles[]>('roles', context.getHandler());

    if (!requiredRoles) {
      return true; // If no roles are defined, allow access
    }

    // Get the request and response from the execution context
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse<Response>();

    // Extract the token from the cookies
    const token = request.cookies['auth_token'];

    if (!token) {
      throw new ForbiddenException('No authentication token found');  // Token not found in cookies
    }

    try {
      // Decode the token to get user data
      const decoded: any = this.jwtService.verify(token);
      console.log("token user role:", decoded.role);

      if (!decoded) {
        throw new ForbiddenException('Invalid token');  // Token is invalid or expired
      }

      // Check if the user's role matches any of the required roles
      if (!requiredRoles.some(role => role === decoded.role)) {
        // If role does not match, throw a custom forbidden error and redirect
        response.redirect('/auth/profile'); // Redirect user to user page if not an admin
        throw new HttpException(
          {
            statusCode: HttpStatus.FORBIDDEN,
            message: 'This page only for admin',
            error: 'Forbidden',
          },
          HttpStatus.FORBIDDEN,
        );
      }

      return true; // Allow access if role matches
    } catch (error) {
      throw new HttpException(
        {
          statusCode: HttpStatus.FORBIDDEN,
          message: 'This page only for admin',
          error: 'Forbidden',
        },
        HttpStatus.FORBIDDEN, // Handle token decode or role check error
      );
    }
  }
}
