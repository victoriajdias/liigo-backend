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
// import { JwtAuthGuard } from 'src/jwt/jwt-auth.guard';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    const { username, password } = body;
    const loginResult = await this.userService.login(username, password);
    return loginResult; // retorna o token e o sub
  }

  @Post('register')
  // @UseGuards(JwtAuthGuard)
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

  @Post('role')
  async createRole(@Body() createRoleDto: CreateRoleDto): Promise<Role> {
    const { name } = createRoleDto;
    return this.userService.createRole(name);
  }

  // listar todas as roles
  //  @Get()
  //  async listRoles(): Promise<Role[]> {
  //    return this.userService.listRoles(); // Método para listar todas as roles
  //  }

  @Get()
  // @UseGuards(JwtAuthGuard)
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
