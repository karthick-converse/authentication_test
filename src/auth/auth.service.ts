import { Injectable, NotFoundException, Res } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Auth } from './entities/auth.entity';
import { Repository } from 'typeorm';
import * as bcrypt  from 'bcryptjs'
import {LoginAuthDto} from './dto/login-auth.dto';
import {  JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { UpdateAuthDto } from './dto/update-auth.dto';
import * as nodemailer from 'nodemailer';
import { VerifyOtpDto } from './dto/verifiy_otp.dto';


@Injectable()
export class AuthService {
    static deleteuser(userId: string) {
        throw new Error('Method not implemented.');
    }
    static getsingle() {
        throw new Error('Method not implemented.');
    }
    static login(loginAuthDto: LoginAuthDto, res: any) {
        throw new Error('Method not implemented.');
    }
     createUser(createAuthDto: { id: number; name: string; password: string; email: string; role: import("./enums/role.enums").Roles; otp: string; otpExpires: Date; verified: boolean; }) {
    throw new Error('Method not implemented.');
  }
  constructor(
    @InjectRepository(Auth) // Inject the repository for the Auth entity
    private authRepository: Repository<Auth>, // Define the type of the repository as Auth
    private  jwtservice:JwtService
  ) {}
  
  greet(){
    return "Hello!";
  }

  async create(createAuthDto: CreateAuthDto, profileImagePath: string,res) {
    try {

      const check_email=await this.authRepository.findOne({where:{email:createAuthDto.email}})
      
      if(!check_email)
      {
      // Hash the password before saving the user
      const hashedPassword = await bcrypt.hash(createAuthDto.password, 10);

      // Create the user object, including the hashed password and profile image path (if available)
      const newUser = {
        ...createAuthDto,
        password: hashedPassword,
        profileImage: profileImagePath, // Store file path if available
      };

      // Save the user to the database
      const savedUser = await this.authRepository.save(newUser);

      return res.redirect('/auth/login')
    }
    return res.redirect('/auth/signup')
    } catch (error) {
      console.error('Error during user creation:', error.message, error.stack);
      throw new Error('Error during user creation');
    }
  }

  async login(loginAuthDto: LoginAuthDto, @Res() res: Response) {
    try {
      // Check if the user exists by email
      const find_email = await this.authRepository.findOne({ where: { email: loginAuthDto.email } });
  
      // If the user is not found, redirect to the signup page
      if (!find_email) {
        return res.redirect('/auth/signup'); // Redirect to signup page
      }
  
      // At this point, TypeScript knows that `find_email` is not null
      const validpass = await bcrypt.compare(loginAuthDto.password, find_email.password);
  
      // If password is invalid, return an error message
      if (!validpass) {
        return res.status(401).json({ message: 'Invalid password' });
      }
  
      // Check if the user is verified
      
        // If user is already verified, create JWT and return the profile
        const payload = { role: find_email.role, id: find_email.id }; // You can add more claims if necessary
        const jwtToken = this.jwtservice.sign(payload); // Generate JWT token
          // Set the JWT token in a cookie called 'auth_token'
      res.cookie('auth_token', jwtToken, {
        httpOnly: true, // Makes the cookie accessible only via HTTP requests (prevents JS access)
        secure: process.env.NODE_ENV === 'production', // Set secure flag only in production (requires HTTPS)
        maxAge: 3600000, // Set cookie expiration time (1 hour in this case)
      });
        // Respond with the JWT token and user profile
        return res.status(200).redirect('/auth/profile');
      // } else {
      //   // If the user is not verified, generate OTP for 2FA
      //   const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit OTP
      //   console.log('Generated OTP:', otp);
  
      //   // Store the OTP temporarily in the database (with expiration)
      //   await this.authRepository.update(find_email.id, {
      //     otp: otp,
      //     otpExpires: Date.now() + 5 * 60 * 1000, // OTP expires in 5 minutes
      //   });
  
      //   // Send OTP to the user's email using Nodemailer
      //   const transporter = nodemailer.createTransport({
      //     service: 'gmail', // or your email service
      //     auth: {
      //       user: 'tkarthick550@gmail.com',
      //       pass: 'jbmr gxek mlya qmrv', // Use environment variables for sensitive info
      //     },
      //     tls: {
      //       rejectUnauthorized: false,  // This is used to allow the connection in case of certificate issues
      //     },
      //     port: 587
      //   });
  
      //   const mailOptions = {
      //     from: 'tkarthick550@gmail.com',
      //     to: find_email.email,
      //     subject: 'Your 2FA OTP',
      //     text: `Your OTP for login is ${otp}. It will expire in 5 minutes.`,
      //   };
  
      //   // Send the OTP email
      //   await transporter.sendMail(mailOptions);
  
      //   // Redirect the user to the OTP verification page
      //   return res.redirect('/auth/profile');
      // }
    } catch (error) {
      console.error('Error during login:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
  

  async getsingle(){
    const users=await this.authRepository.find();
    return {users};
  }

  async deleteuser(id: string){
    try {
      // Call the repository method to delete the user
      const result = await this.authRepository.delete(id);
      if (result.affected === 0) {
        throw new Error('User not found');
      }
      return result;  // Return the result (true if successful, false if not)
    } catch (error) {
      // If something goes wrong, throw an error
      throw new Error('Error deleting user');
    }
  }



  async updateUser(id: string, p0: {}): Promise<Auth> {
    const user = await this.authRepository.findOne({ where: { id:Number(id) } });
    console.log("update user:",user);
    
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  // Update user method in the service
  async updatedUser(id: string, updateAuthDto: UpdateAuthDto, @Res() res: Response) {
    // Fetch the user first to check if it exists
    const user = await this.authRepository.findOne({ where: { id: Number(id) } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
  
    try {
      // Perform the update
      await this.authRepository.update(id, updateAuthDto);
    } catch (error) {
      console.error('Error during user creation:', error.message, error.stack);
      throw new Error('Error updating user'); // Throw a specific error message here
    }
  
    // Redirect to profile or wherever you want after the update
    return res.redirect('/auth/users');
  }
  


 
}

