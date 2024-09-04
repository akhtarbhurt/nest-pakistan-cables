import { IsEmail, IsNotEmpty, IsString, IsOptional, isString } from 'class-validator';

export class CreateUserDto {
    @IsNotEmpty()
    @IsString()
    userName: string;
  
    @IsNotEmpty()
    @IsEmail()
    email: string;
  
    @IsNotEmpty()
    @IsString()
    position: string;
  
    @IsNotEmpty()
    @IsString()
    department: string;
  
    @IsNotEmpty()
    @IsString()
    role: string;
  
    @IsNotEmpty()
    @IsString()
    password: string;
    
    @IsNotEmpty()
    status: string;
  }


  