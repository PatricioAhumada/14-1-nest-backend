import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import * as request from 'supertest';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtService: JwtService ,
    private authService : AuthService
  ) {}
  
  //   context: executioncontext,
  // ): boolean | promise<boolean> | observable<boolean> { //retorna un boolean o una promesa o observable
  async canActivate( context: ExecutionContext ): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    //console.log({request});
    const token = this.extractTokenFromHeader(request);
    //console.log({token});
    if (!token) {
      throw new UnauthorizedException('There is no bearer Token');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token,
        {
          secret: process.env.JWT_SEED
        }
      );
      //console.log({payload});
      const user = await this.authService.findUserById(payload.id);      
      if( !user ) throw new UnauthorizedException('User doesn´t exists!');
      if( !user.isActive ) throw new UnauthorizedException('User is not active!');
      //request['user'] = payload.id;
      request['user'] = user ;

    } catch (error) {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
