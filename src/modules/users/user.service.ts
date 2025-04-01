import * as dotenv from 'dotenv';
dotenv.config();

import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserAttribute,
} from 'amazon-cognito-identity-js';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import bcrypt from 'bcryptjs';
import { Role } from '../entities/role.entity';
import { UserDto } from './dto/user.dto';
// import { JwtService } from '@nestjs/jwt';

const poolData = {
  UserPoolId: process.env.AWS_USER_POOL_ID!,
  ClientId: process.env.AWS_CLIENT_ID!,
};

const userPool = new CognitoUserPool(poolData);

console.log('userPool', userPool);

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    private readonly userPool: CognitoUserPool,
    // private readonly jwtService: JwtService,
  ) {}

  // criar uma Role
  async createRole(name: string): Promise<Role> {
    const existingRole = await this.roleRepository.findOne({ where: { name } });
    if (existingRole) {
      return existingRole;
    }
    const role = this.roleRepository.create({ name });
    return this.roleRepository.save(role);
  }

  async login(username: string, password: string): Promise<any> {
    const userData = {
      Username: username,
      Pool: userPool,
    };

    const cognitoUser = new CognitoUser(userData);
    const authenticationDetails = new AuthenticationDetails({
      Username: username,
      Password: password,
    });

    return new Promise(async (resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: async (result) => {
          const idToken = result.getIdToken().getJwtToken();
          const payload = JSON.parse(atob(idToken.split('.')[1]));
          const userSub = payload.sub;

          try {
            let user = await this.userRepository.findOne({
              where: { email: username },
            });

            if (!user) {
              return reject(
                new UnauthorizedException('Usuário não encontrado.'),
              );
            }

            // const jwtToken = this.jwtService.sign({ sub: userSub, username });

            resolve({
              token: idToken,
              sub: userSub,
              // isAdmin: user.isAdmin ?? false,
            });
          } catch (err) {
            console.error('Erro ao consultar banco:', err);
            return reject(
              new UnauthorizedException('Erro ao consultar o banco de dados.'),
            );
          }
        },
        onFailure: (err) => {
          return reject(
            new UnauthorizedException(
              err.message || 'Erro ao autenticar usuário',
            ),
          );
        },
      });
    });
  }

  async signUp(UserDto: UserDto): Promise<any> {
    const { email, password, username, name, role } = UserDto;

    // Se a role foi passada, buscar a role no banco
    let roleEntity: Role | null = null;
    if (role) {
      roleEntity = await this.roleRepository.findOne({ where: { id: role } });
    }

    // Caso a role não tenha sido passada, podemos criar uma role padrão
    if (!roleEntity) {
      roleEntity = await this.createRole('User'); // Cria a role 'User' por padrão
    }

    const attributeList = [
      new CognitoUserAttribute({
        Name: 'email',
        Value: email,
      }),
    ];

    return new Promise((resolve, reject) => {
      this.userPool.signUp(
        email,
        password,
        attributeList,
        [],
        async (err, result) => {
          if (err) {
            reject(err);
          } else {
            const newUser = this.userRepository.create({
              email,
              password,
              username,
              name,
              role: roleEntity, // Atribuindo a role ao usuário
              confirmCode: result?.userConfirmed || false,
            });

            const savedUser = await this.userRepository.save(newUser);

            resolve({
              message:
                'Usuário registrado com sucesso. Por favor, confirme seu e-mail.',
              user: savedUser,
            });
          }
        },
      );
    });
  }

  async confirmUser(username: string, confirmationCode: string): Promise<any> {
    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: userPool,
    });

    return new Promise((resolve, reject) => {
      cognitoUser.confirmRegistration(
        confirmationCode,
        true,
        async (err, result) => {
          if (err) {
            console.error('Erro ao confirmar o registro:', err);
            reject(new UnauthorizedException('Erro ao confirmar o usuário.'));
          } else {
            console.log('Usuário confirmado com sucesso:', result);

            try {
              await this.userRepository.update(
                { email: username },
                { confirmCode: true },
              );

              resolve({
                message: 'Usuário confirmado com sucesso.',
              });
            } catch (error) {
              console.error('Erro ao atualizar banco de dados:', error);
              reject(
                new ConflictException(
                  'Erro ao atualizar o banco de dados após confirmação.',
                ),
              );
            }
          }
        },
      );
    });
  }

  async listUsers(): Promise<User[]> {
    return this.userRepository.find();
  }

  // async updateUser(id: string) {
  //   await this.userRepository.update(id);
  //   // return this.userRepository.findOne({ where: { id } });
  // }

  async deleteUser(id: string): Promise<void> {
    await this.userRepository.delete(id);
  }
}
