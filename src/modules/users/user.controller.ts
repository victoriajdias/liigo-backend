import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  Put,
  Delete,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { UserService } from './user.service';
import { User } from '../entities/user.entity';
import { Role } from '../entities/role.entity';
import { UserDto } from './dto/user.dto';
import { CreateRoleDto } from './dto/role.dto';
import { JwtAuthGuard } from '../jwt/jwt-auth.guard';

@Controller('auth')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    const { username, password } = body;
    const loginResult = await this.userService.login(username, password);
    return loginResult;
  }

  @Post('refresh')
  async refresh(@Body('refreshToken') refreshToken: string) {
    return this.userService.refreshToken(refreshToken);
  }

  @Post('register')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  async signUp(@Body() signUpDto: UserDto) {
    console.log('dados:', signUpDto);
    return this.userService.signUp(signUpDto);
  }

  @Post('confirm')
  async confirmUser(
    @Body('username') username: string,
    @Body('confirmationCode') confirmationCode: string,
  ) {
    return this.userService.confirmUser(username, confirmationCode);
  }

  @Post('resend-confirmation')
  async resendConfirmation(@Body('email') email: string) {
    return this.userService.resendConfirmationCode(email);
  }

  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    return this.userService.forgotPassword(email);
  }

  @Post('reset-password')
  async resetPassword(
    @Body('email') email: string,
    @Body('code') code: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.userService.resetPassword(email, code, newPassword);
  }

  @Post('role')
  async createRole(@Body() createRoleDto: CreateRoleDto): Promise<Role> {
    const { name } = createRoleDto;
    return this.userService.createRole(name);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async listUsers(): Promise<User[]> {
    return this.userService.listUsers();
  }

  // @Put(':id')
  // @UseGuards(JwtAuthGuard)
  // async updateUser(
  //   @Param('id') id: string,
  //   @Body() updateData: Partial<User>,
  // ): Promise<User> {
  //   return this.userService.updateUser(id, updateData);
  // }

  @Delete(':id')
  // @UseGuards(JwtAuthGuard)
  async deleteUser(@Param('id') id: string): Promise<{ message: string }> {
    await this.userService.deleteUser(id);
    return { message: 'Usuário excluído com sucesso' };
  }
}
