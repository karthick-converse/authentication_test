import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsEnum, IsNotEmpty, MinLength} from "class-validator";



export class UpdateAuthDto {
        @IsNotEmpty()
        @ApiProperty()
        name:string;
        
        @IsNotEmpty()
        @IsEmail({},{message:"pleace enter crt email"})
        @ApiProperty()
        email:string;
        
        
}
