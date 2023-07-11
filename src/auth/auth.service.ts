import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    const newUser = await this.prismaService.user.create({
      data: {
        email: dto.email,
        hash: hash,
      },
    });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRTHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('Access Denied');
    }
    const passwordMatches = await argon.verify(user.hash, dto.password);
    if (!passwordMatches) {
      throw new ForbiddenException('Access Denied');
    }
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRTHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refreshTokens(userId: number, rt: string) {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user) throw new ForbiddenException('Access Denied');

    const rtMatches = argon.verify(user.hashedRt, rt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRTHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async updateRTHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async hashData(data: string) {
    return await argon.hash(data);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email: email,
        },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email: email,
        },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
    ]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
