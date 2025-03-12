import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = request.cookies['auth_token'];  // Get the token from the cookies

    if (!token) {
      return false;
    }

    try {
      // Verify the token
      const decoded = this.jwtService.verify(token);
      const user =request.user = decoded;  // Attach the user info to the request
      console.log("token user :",user);
      
      return true;
    } catch (err) {
      return false;
    }
  }
}
