import { IsEmail, IsNotEmpty, IsString, MinLength, minLength } from "class-validator";


export class LoginAuthDto{
        @IsNotEmpty()
        @MinLength(6,{message:"pleace enter 6 digit number or string"})
        password:string;
    
        @IsNotEmpty()
        @IsEmail({},{message:"pleace enter crt email"})
        email:string;


}
