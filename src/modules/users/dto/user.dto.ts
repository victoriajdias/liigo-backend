// configy
import { IsEmail, IsNotEmpty, IsOptional, MinLength } from 'class-validator';

export class UserDto {
  @IsEmail({}, { message: 'O e-mail deve ser válido.' })
  email: string;

  @IsNotEmpty({ message: 'O nome de usuário é obrigatório.' })
  username: string;

  @IsNotEmpty({ message: 'A senha é obrigatória.' })
  @MinLength(6, { message: 'A senha deve ter pelo menos 6 caracteres.' })
  password: string;

  @IsOptional()
  name?: string;

  @IsOptional()
  role?: string;
}
