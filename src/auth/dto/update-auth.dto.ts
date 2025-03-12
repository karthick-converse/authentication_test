import { IsEmail, IsEnum, IsNotEmpty, MinLength} from "class-validator";



export class UpdateAuthDto {
        @IsNotEmpty()
        name:string;
        
        @IsNotEmpty()
        @IsEmail({},{message:"pleace enter crt email"})
        email:string;
        
        
}
