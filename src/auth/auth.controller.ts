import { Controller, Get, Post, Body, Request, UseGuards, Render, Res, Param, Delete, UseInterceptors, UploadedFile } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import {UpdateAuthDto} from './dto/update-auth.dto' ;
import { RolesGuard } from './guards/roles.guard';
// import { JwtAuthGuard } from './guards/Jwt.guard';
import { Role } from './decorators/role.decorators';
import { Roles } from './enums/role.enums';
import { Response } from 'express';
import { JwtAuthGuard } from './guards/Jwt.guard';
import { diskStorage } from 'multer';
import * as fs from 'fs';

import { FileInterceptor } from '@nestjs/platform-express';
import { VerifyOtpDto } from './dto/verifiy_otp.dto';
import { ApiTags } from '@nestjs/swagger';
// Define the upload directory
const UPLOADS_DIR = './uploads';
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR);
}

@Controller('auth')
export class AuthController {
    
  constructor(private readonly authService: AuthService) {}


  
  @Get('signup')
  @Render('signup') 
  signupPage() {
    return {};  // You can pass any data here if needed
  }

// Route to create a user
@Post('signup')
@UseInterceptors(
  FileInterceptor('profileImage', {
    storage: diskStorage({
      destination: UPLOADS_DIR,  // Specify the upload directory
      filename: (req, file, cb) => {
        const filename = `${Date.now()}-${file.originalname}`;
        cb(null, filename); // Give each file a unique name
      },
    }),
  })
)
async create(@Body() createAuthDto: CreateAuthDto,@Res() res:Response, @UploadedFile() file: Express.Multer.File,
) {
  const profileImagePath =file ? file.path : '' // File path for the uploaded image
   console.log("profile file path:",profileImagePath);
   
  const user = await this.authService.create(createAuthDto, profileImagePath,res);
  res.status(201).json(user)
}
 
 
 
  @Get('login')
  @ApiTags('login')
  @Render('login') 
  loginPage() {
    return {};  // You can pass any data here if needed
  }
  
  @Post('login')
  async login(@Body() loginAuthDto: LoginAuthDto, @Res() res: Response) {
    return this.authService.login(loginAuthDto, res); // Pass the response object to the service
  }

  @Get('verify-otp')
  @Render('otppage')
  otppage(){
    return {}
  }

@Post('verify-otp')
verifyotp(@Body() verifyOtp:VerifyOtpDto,@Res() Res: Response){
 return this.authService.otpverify(verifyOtp,Res)
}

  @Get('logout')
  clearCookie(@Res() res: Response) {
    res.clearCookie('auth_token', {
      httpOnly: true, // Match the same options as the login cookie
      secure: true,   // Make sure secure flag matches your login cookie
    });
  
    // Return a message or redirect after logging out
    return res.redirect('/auth/login');
  }

  @UseGuards(JwtAuthGuard) // Only allow authenticated users (JWT)
  @Get('/profile')
  @Render('profile')
  async getprofile(@Request() req) {
    
    return {user:req.user};  // Assuming user object contains email
  }


  @Get('/users')  
  @UseGuards(JwtAuthGuard, RolesGuard) // Apply both AuthGuard and RolesGuard
  @Role( Roles.moderator,Roles.admin) 
  @Render('userview')
  getsingleuser() {
    return this.authService.getsingle();
  }



    
  @Get('/update/:id')
  @Render('updateForm')
  @UseGuards(JwtAuthGuard,RolesGuard)
  @Role(Roles.admin)
  async update(@Param('id') id: string, @Res() res: Response) {
    const user = await this.authService.updateUser(id, {});
    // Pass user data to the view
    return { user };  // 
  }

  @Post('/update/:id')
  @UseGuards(JwtAuthGuard,RolesGuard)
  @Role(Roles.admin)
  async updatedUser(
    @Param('id') id: string,
    @Body() updateAuthDto: UpdateAuthDto,
    @Res() res: Response
  ) {
    await this.authService.updatedUser(id, updateAuthDto, res);
  }

  
  @Get('/delete/:id')
  @UseGuards(JwtAuthGuard,RolesGuard)
  @Role(Roles.admin)
  async deleteUser(@Param('id') id: string, @Res() res: Response) {
    try {
      // Call the service method to delete the user
      const result = await this.authService.deleteuser(id);

      if (!result) {
        // If the user was not found, return 404
        return res.status(404).send({ message: `User with ID ${id} not found.` });
      }

      // If deletion is successful, return 200
      return res.redirect('/auth/users')
    } catch (error) {
      // If there's an error during the deletion process, return 500
      return res.status(500).send({ message: 'An error occurred while deleting the user.', error });
    }
  
  }

}
