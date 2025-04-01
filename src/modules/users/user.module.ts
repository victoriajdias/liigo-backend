import * as dotenv from 'dotenv';
dotenv.config();
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { User } from '../entities/user.entity';
import { Role } from '../entities/role.entity';
import { CognitoUserPool } from 'amazon-cognito-identity-js';
// import { JwtModule } from '@nestjs/jwt';
// import { JwtStrategy } from 'src/jwt/jwt.strategy';
@Module({
  imports: [
    TypeOrmModule.forFeature([User, Role]),
    // JwtModule.register({
    //   secret: process.env.JWT_SECRET,
    //   signOptions: { expiresIn: '1h' },
    // }),
  ],
  controllers: [UserController],
  providers: [
    UserService,
    {
      provide: CognitoUserPool,
      useFactory: () => {
        const poolData = {
          UserPoolId: process.env.AWS_USER_POOL_ID!,
          ClientId: process.env.AWS_CLIENT_ID!,
        };
        return new CognitoUserPool(poolData);
      },
    },
  ],
  exports: [UserService],
})
export class UserModule {}
