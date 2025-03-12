import { IsEmail, IsEnum, isNotEmpty, IsNotEmpty, IsString, Matches, MaxLength, MinLength} from "class-validator";
import { Roles } from "../enums/role.enums";


export class CreateAuthDto {
        @IsNotEmpty()
        name:string;
    
        @IsNotEmpty({ message: 'Password is required' })
        @MinLength(6, { message: 'Please enter at least 6 characters for the password' })
        @MaxLength(20, { message: 'Password cannot be longer than 20 characters' })
        @Matches(/(?=.*[a-z])/, { message: 'Password must contain at least one lowercase letter' })  // At least one lowercase letter
        @Matches(/(?=.*[A-Z])/, { message: 'Password must contain at least one uppercase letter' })  // At least one uppercase letter
        @Matches(/(?=.*\d)/, { message: 'Password must contain at least one number' })  // At least one number
        @Matches(/(?=.*[@$!%*?&])/, { message: 'Password must contain at least one special character (e.g., @$!%*?&)' })  // At least one special character
        @IsString({ message: 'Password must be a string' })
        password: string;
    
        @IsNotEmpty()
        @IsEmail({},{message:"pleace enter crt email"})
        email:string;
        
        @IsEnum(Roles)
        role: Roles;
        
}

