import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { Auth } from './entities/auth.entity';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { Roles } from './enums/role.enums';
import { LoginAuthDto } from './dto/login-auth.dto';
import * as nodemailer from 'nodemailer';



describe('AuthService', () => {
  let authService: AuthService;
  let authRepository: Repository<Auth>;
  let jwtService: JwtService;
  let bcryptHashSpy: jest.SpyInstance;
  let bcryptCompareSpy: jest.SpyInstance;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(Auth),
          useValue: {
            find: jest.fn(),  // Mock 'find' method on the repository instance
            findOne: jest.fn(),
            save: jest.fn(),
            delete: jest.fn(), // Mock 'delete' method on the repository instance
            update: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
            verify: jest.fn(),
          },
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    authRepository = module.get<Repository<Auth>>(getRepositoryToken(Auth));  // Get repository instance
    jwtService = module.get<JwtService>(JwtService);
    bcryptHashSpy = jest.spyOn(bcrypt, 'hash');
    bcryptCompareSpy = jest.spyOn(bcrypt, 'compare');
  });

  // Test case for greet function
  it('should return the correct greeting message from greet()', () => {
    expect(authService.greet()).toBe('Hello!');
  });

  // Test case for create function (user creation)
  it('should create a new user and redirect to /auth/login', async () => {
    const createAuthDto = {
      name: 'John Doe',
      password: 'password123', // Valid password
      email: 'john.doe@example.com',
      role: Roles.user,
    };
    const profileImagePath = '/path/to/profile-image.jpg';

    // Mock bcrypt.hash to return a fake hashed password
    bcryptHashSpy.mockResolvedValue('hashedPassword123');

    // Mock the save method of the repository to simulate saving a user
    (authRepository.save as jest.Mock).mockResolvedValue({
      ...createAuthDto,
      password: 'hashedPassword123',
      profileImage: profileImagePath,
    });

    // Mock the response object (for redirect)
    const res = { redirect: jest.fn() } as any;

    // Call the create method
    await authService.create(createAuthDto, profileImagePath, res);

    // Verify that bcrypt.hash was called with the correct password
    expect(bcryptHashSpy).toHaveBeenCalledWith(createAuthDto.password, 10);

    // Verify that save was called with the correct data
    expect(authRepository.save).toHaveBeenCalledWith({
      ...createAuthDto,
      password: 'hashedPassword123',
      profileImage: profileImagePath,
    });

    // Verify that redirect was called with the correct URL
    expect(res.redirect).toHaveBeenCalledWith('/auth/login');
  });

  // Test case for user creation failure
  it('should throw an error when user creation fails', async () => {
    const createAuthDto = {
      name: 'Test User',
      email: 'test@example.com',
      password: 'password123',
      role: Roles.user,
    };
    const profileImagePath = '/path/to/profile-image.jpg';

    // Simulate an error when saving the user to the database
    (authRepository.save as jest.Mock).mockRejectedValue(new Error('Database error'));

    const res = { redirect: jest.fn() } as any;

    // Call the create method and check for thrown error
    await expect(authService.create(createAuthDto, profileImagePath, res)).rejects.toThrowError(
      'Error during user creation',
    );
  });

  // Test case for login - user not found
  it('should redirect to signup page if user not found', async () => {
    const loginAuthDto: LoginAuthDto = {
      email: 'test@example.com',
      password: 'password123',
    };

    // Mock the findOne method to simulate user not found
    (authRepository.findOne as jest.Mock).mockResolvedValue(null);

    const res = { redirect: jest.fn() } as any;

    await authService.login(loginAuthDto, res);

    expect(res.redirect).toHaveBeenCalledWith('/auth/signup');
  });

  // Test case for login - invalid password
  it('should return 401 if password is invalid', async () => {
    const loginAuthDto: LoginAuthDto = {
      email: 'test@example.com',
      password: 'password123',
    };

    const fakeUser = {
      id: 1,
      email: 'test@example.com',
      password: 'hashedPassword123',
      role: Roles.user,
    };

    // Mock the findOne method to simulate user found
    (authRepository.findOne as jest.Mock).mockResolvedValue(fakeUser);

    // Mock bcrypt.compare to return false, simulating invalid password
    bcryptCompareSpy.mockResolvedValue(false);

    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;

    await authService.login(loginAuthDto, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: 'Invalid password' });
  });

  // Test case for login - successful login
it('should redirect to profile and set JWT cookie if login is successful', async () => {
  const loginAuthDto: LoginAuthDto = {
    email: 'test@example.com',
    password: 'password123',
  };

  const fakeUser = {
    id: 1,
    email: 'test@example.com',
    password: 'hashedPassword123',
    role: Roles.user,
    verified: true, // Assuming user is verified in this case
  };

  // Mock the findOne method to simulate the user being found
  (authRepository.findOne as jest.Mock).mockResolvedValue(fakeUser);

  // Mock bcrypt.compare to return true, simulating valid password
  bcryptCompareSpy.mockResolvedValue(true);

  // Mock JwtService sign method
  (jwtService.sign as jest.Mock).mockReturnValue('fake-jwt-token');

  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
    cookie: jest.fn(),
    redirect: jest.fn(),
  } as any;

  // Call the login method
  await authService.login(loginAuthDto, res);

  // Assert bcrypt.compare was called with correct arguments
  expect(bcryptCompareSpy).toHaveBeenCalledWith(loginAuthDto.password, fakeUser.password);

  // Assert JwtService sign was called with the correct payload
  expect(jwtService.sign).toHaveBeenCalledWith({ role: fakeUser.role, id: fakeUser.id });

  // Assert the cookie was set correctly with the JWT token
  expect(res.cookie).toHaveBeenCalledWith('auth_token', 'fake-jwt-token', {
    httpOnly: true,
    secure: false,
    maxAge: 3600000,
  });

  // Assert redirection to profile
  expect(res.redirect).toHaveBeenCalledWith('/auth/profile');
});

// Test case for login - invalid password
it('should return 401 status if password is invalid', async () => {
  const loginAuthDto: LoginAuthDto = {
    email: 'test@example.com',
    password: 'wrongpassword',
  };

  const fakeUser = {
    id: 1,
    email: 'test@example.com',
    password: 'hashedPassword123',
    role: Roles.user,
    verified: true, // Assuming user is verified
  };

  // Mock the findOne method to simulate user found
  (authRepository.findOne as jest.Mock).mockResolvedValue(fakeUser);

  // Mock bcrypt.compare to return false, simulating invalid password
  bcryptCompareSpy.mockResolvedValue(false);

  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
    cookie: jest.fn(),
    redirect: jest.fn(),
  } as any;

  // Call the login method
  await authService.login(loginAuthDto, res);

  // Assert bcrypt.compare was called with the correct arguments
  expect(bcryptCompareSpy).toHaveBeenCalledWith(loginAuthDto.password, fakeUser.password);

  // Assert that a 401 status is returned with an error message
  expect(res.status).toHaveBeenCalledWith(401);
  expect(res.json).toHaveBeenCalledWith({ message: 'Invalid password' });
});

// Test case for login - unverified user (OTP flow)
it('should redirect to OTP verification if user is unverified', async () => {
  const loginAuthDto: LoginAuthDto = {
    email: 'test@example.com',
    password: 'password123',
  };

  const fakeUser = {
    id: 1,
    email: 'test@example.com',
    password: 'hashedPassword123',
    role: Roles.user,
    verified: false, // User is not verified
  };

  // Mock the findOne method to simulate user found
  (authRepository.findOne as jest.Mock).mockResolvedValue(fakeUser);

  // Mock bcrypt.compare to return true, simulating valid password
  bcryptCompareSpy.mockResolvedValue(true);

  // Mock Nodemailer transporter to avoid sending real emails during tests
  const transporterSpy = jest.spyOn(nodemailer, 'createTransport').mockReturnValue({
    sendMail: jest.fn(),
  } as any);

  // Mock JwtService sign method to avoid JWT creation
  (jwtService.sign as jest.Mock).mockReturnValue('fake-jwt-token');

  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
    cookie: jest.fn(),
    redirect: jest.fn(),
  } as any;

  // Call the login method
  await authService.login(loginAuthDto, res);

  // Assert that the OTP email is being generated and sent (mocked)
  expect(transporterSpy).toHaveBeenCalled();

  // Assert redirection to OTP verification page
  expect(res.redirect).toHaveBeenCalledWith('/auth/verify-otp');
});


  // Test case for updateUser method - User found
  it('should return a user if user exists', async () => {
    const userId = '1';
    const mockUser = { id: 1, name: 'John Doe', email: 'john.doe@example.com' };

    (authRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

    const result = await authService.updateUser(userId, {});

    expect(authRepository.findOne).toHaveBeenCalledWith({ where: { id: Number(userId) } });
    expect(result).toEqual(mockUser);
  });

  // Test case for updateUser method - User not found
  it('should throw an error if user does not exist', async () => {
    const userId = '1';

    (authRepository.findOne as jest.Mock).mockResolvedValue(null);

    await expect(authService.updateUser(userId, {})).rejects.toThrowError('User with ID 1 not found');
  });

  // Test case for updatedUser method - User successfully updated
  it('should update the user and redirect to /auth/users', async () => {
    const userId = '1';
    const updateAuthDto = { name: 'Jane Doe',email: 'john.doe@example.com'};
    const mockUser = { id: 1, name: 'John Doe', email: 'john.doe@example.com' };

    (authRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

    (authRepository.update as jest.Mock).mockResolvedValue({ affected: 1 });

    const res = { redirect: jest.fn() } as any;

    await authService.updatedUser(userId, updateAuthDto, res);

    expect(authRepository.update).toHaveBeenCalledWith(userId, updateAuthDto);
    expect(res.redirect).toHaveBeenCalledWith('/auth/users');
  });

  // Test case for updatedUser method - User not found
  it('should throw an error if user does not exist', async () => {
    const userId = '1';
    const updateAuthDto = { name: 'Jane Doe',email: 'john.doe@example.com' };

    (authRepository.findOne as jest.Mock).mockResolvedValue(null);

    const res = { redirect: jest.fn() } as any;

    await expect(authService.updatedUser(userId, updateAuthDto, res)).rejects.toThrowError('User with ID 1 not found');
  });

  // Test case for updatedUser method - Update fails
  it('should throw an error if there is an issue with the update', async () => {
    const userId = '1';
    const updateAuthDto = { name: 'Jane Doe',email: 'john.doe@example.com'};
    const mockUser = { id: 1, name: 'John Doe', email: 'john.doe@example.com' };

    (authRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

    (authRepository.update as jest.Mock).mockRejectedValue(new Error('Database error'));

    const res = { redirect: jest.fn() } as any;

    await expect(authService.updatedUser(userId, updateAuthDto, res)).rejects.toThrowError('Error updating user');
  });
});
