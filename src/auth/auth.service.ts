import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto , UpdateAuthDto , LoginDto , RegisterUserDto } from './dto';
import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterResponse } from './interfaces/register-response';
import { log } from 'console';

@Injectable()
export class AuthService {

  constructor(
    //@InjectModel(User.name, 'users') private userModel: Model<User> forma 1
    @InjectModel(User.name) private userModel: Model<User>,//forma 2
    private jwtService : JwtService
  ){}

  async create(createUserDto: CreateUserDto):Promise<User> {    
    try {
      //const newUser = new this.userModel( createUserDto );//Forma 1: sin encriptado de password
      //forma 2
      const { password , ...userData } = createUserDto;            
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password , 10),
        ...userData
      });

      await newUser.save();
      //lo hacemos para evitar enviar la password como respuesta
      const { password:_ , ...user } = newUser.toJSON();       
      return user;      
    } catch (error) {
      console.log(error.code)
      if(error.code === 11000 ){
        throw new BadRequestException(`${ createUserDto.email} already exist !!`);
      }
      throw new InternalServerErrorException(' Something terrible happen!!!!!')
    }
  }

  async login( logindto : LoginDto ) :Promise<LoginResponse>{
    //console.log({ logindto })
    const { email , password } = logindto;    
    const user = await this.userModel.findOne({email:email})

    if( !user){
      throw new UnauthorizedException('Not valid credentials (e)')
    }

    if( !bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Not valid credentials (p)')
    }

    const { password:_ , ...rest } = user.toJSON(); //en rest recuerda que viene el resto de la información

    return {
      user : rest,
      token: this.getJwtToken({ id: user.id })
    };
  }

  async register( registerUserDto : RegisterUserDto ): Promise<RegisterResponse>{

    const user = await this.create( registerUserDto );
    console.log();
    return {
      user : user,
      token: this.getJwtToken({ id: user._id })
    };
  }

  getJwtToken( payload : JwtPayload ){
    const token = this.jwtService.sign(payload);
    return token;
  }
  
  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id:string ){
    const user = await this.userModel.findById( id )
    const { password , ...rest } = user.toJSON();
    return rest;
  }



  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
