import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { IsOptional } from 'class-validator';
import { Role } from './role.entity';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true })
  @IsOptional()
  name?: string;

  @Column({ nullable: true })
  @IsOptional()
  username?: string;

  @Column({ unique: true, nullable: false, length: 255 })
  email: string;

  @Column()
  password: string;

  @ManyToOne(() => Role, (role) => role.users)
  @IsOptional()
  role?: Role;

  @Column()
  @IsOptional()
  confirmCode?: boolean;
}
