
import { Controller, Get, Post, Body, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';

import { CreateUserDto , UpdateAuthDto , LoginDto , RegisterUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/login-response';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto){
    return this.authService.login(loginDto);
  }

  @Post('/register')
  register(@Body() registerUserDto: RegisterUserDto){
    return this.authService.register(registerUserDto);
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll(@Request() req: Request) {
    //console.log(req)
    const user = req['user'];
    //return user;  
    return this.authService.findAll();
  }

  @UseGuards( AuthGuard )
  @Get('check-token')
  checkToken(@Request() req: Request ): LoginResponse{
    
    const user = req['user'] as User;    
    return {
      user:user,
      token: this.authService.getJwtToken({ id:user._id })
    }
    
  }
  

  // @get(':id')
  // findone(@param('id') id: string) {
  //   return this.authservice.findone(+id);
  // }

  // @patch(':id')
  // update(@param('id') id: string, @body() updateauthdto: updateauthdto) {
  //   return this.authservice.update(+id, updateauthdto);
  // }

  // @delete(':id')
  // remove(@param('id') id: string) {
  //   return this.authservice.remove(+id);
  // }
}
