import * as dotenv from 'dotenv';
dotenv.config();

import {
  BadRequestException,
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
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    private readonly userPool: CognitoUserPool,
    private readonly jwtService: JwtService,
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
      Pool: this.userPool,
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

            // Gerar tokens
            const accessToken = this.jwtService.sign(
              { sub: userSub, username },
              { expiresIn: '1d' }, // Expira em 1 dia
            );

            const refreshToken = this.jwtService.sign(
              { sub: userSub },
              { expiresIn: '7d' }, // Expira em 7 dias
            );
            resolve({
              accessToken,
              refreshToken,
              sub: userSub,
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

  async refreshToken(refreshToken: string): Promise<any> {
    try {
      // Verifica se o refresh token é válido
      const decoded = this.jwtService.verify(refreshToken);

      // Gerar um novo Access Token
      const newAccessToken = this.jwtService.sign(
        { sub: decoded.sub },
        { expiresIn: '1d' }, // Expira em 1 dia
      );

      return { accessToken: newAccessToken };
    } catch (err) {
      throw new UnauthorizedException('Refresh Token inválido ou expirado.');
    }
  }

  async signUp(UserDto: UserDto): Promise<any> {
    const { email, password, username, name, role } = UserDto;

    // se a role foi passada, buscar a role no banco
    let roleEntity: Role | null = null;
    if (role) {
      roleEntity = await this.roleRepository.findOne({ where: { id: role } });
    }

    // criar uma role padrão, caso a mesma nao teha sido passada
    if (!roleEntity) {
      roleEntity = await this.createRole('User'); // cria a role 'User' por padrão
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
              role: roleEntity,
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
      Pool: this.userPool,
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

  async resendConfirmationCode(username: string): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { email: username },
    });

    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado.');
    }

    if (user.confirmCode) {
      throw new BadRequestException('Usuário já está confirmado.');
    }

    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: this.userPool,
    });

    return new Promise((resolve, reject) => {
      cognitoUser.resendConfirmationCode((err, result) => {
        if (err) {
          reject(
            new UnauthorizedException(
              err.message || 'Erro ao reenviar código de confirmação.',
            ),
          );
        } else {
          resolve({
            message: 'Código de confirmação reenviado para o e-mail.',
          });
        }
      });
    });
  }

  async forgotPassword(username: string): Promise<any> {
    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: this.userPool,
    });

    return new Promise((resolve, reject) => {
      cognitoUser.forgotPassword({
        onSuccess: (data) => {
          resolve({ message: 'Código de redefinição enviado para o e-mail.' });
        },
        onFailure: (err) => {
          reject(
            new UnauthorizedException(
              err.message || 'Erro ao solicitar redefinição de senha.',
            ),
          );
        },
      });
    });
  }

  async resetPassword(
    email: string,
    code: string,
    newPassword: string,
  ): Promise<any> {
    const cognitoUser = new CognitoUser({
      Username: email,
      Pool: this.userPool,
    });

    return new Promise((resolve, reject) => {
      cognitoUser.confirmPassword(code, newPassword, {
        onSuccess: async () => {
          try {
            // Atualiza a senha no banco de dados
            await this.userRepository.update(
              { email },
              { password: newPassword }, // Idealmente, deve ser criptografada
            );

            resolve({
              message: 'Senha redefinida com sucesso.',
            });
          } catch (error) {
            console.error('Erro ao atualizar a senha no banco:', error);
            reject(
              new ConflictException(
                'Erro ao atualizar a senha no banco de dados.',
              ),
            );
          }
        },
        onFailure: (err) => {
          console.error('Erro ao redefinir senha:', err);
          reject(new UnauthorizedException('Erro ao redefinir senha.'));
        },
      });
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
