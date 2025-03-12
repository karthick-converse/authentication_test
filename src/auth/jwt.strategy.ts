import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { InjectRepository } from "@nestjs/typeorm";
import { Strategy } from "passport-jwt";
import { Repository } from "typeorm";
import { Auth } from "./entities/auth.entity";  // Assuming Auth entity is in 'entities/auth.entity'
import { JwtService } from "@nestjs/jwt";  // Import JwtService for token validation
import { ExtractJwt } from "passport-jwt";  // For extracting JWT from request headers

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(Auth) 
    private authRepository: Repository<Auth>,  // Inject Auth repository
    private jwtService: JwtService  // Inject JwtService to verify the token
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),  // Extract JWT from the Authorization header
      secretOrKey: 'Karthickbackend',  // Secret key used for verifying the JWT
    });
  }

  // Validate the user based on the JWT payload
  async validate(payload: any) {
    // Here, you can extract the user details from the payload
    // For example, you might have the user ID or email in the payload
    const { sub: userId, role } = payload;

    // You can use the user ID or email from the JWT payload to find the user in the database
    const user = await this.authRepository.findOne({ where: { id: userId, role } });

    if (!user) {
      throw new Error(' fist login then access this page');
    }

    return user;  
  }
}
