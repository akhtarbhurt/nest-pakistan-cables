import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTeamDto, UpdateTeamDto, SearchAndFilterTeamsDto } from './dto/team-management.dto';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class TeamManagementService {
  constructor(private readonly prisma: PrismaService) {}

  async validateMembers(members: string[]) {
    return await this.prisma.user.findMany({
      where: { id: { in: members } },
      select: { id: true }
    });
  }

  validateTeamPerformance(teamPerformance: any[]) {
    if (teamPerformance) {
      const isValid = teamPerformance.every(performance =>
        typeof performance.metric === 'string' && typeof performance.value === 'number'
      );

      if (!isValid) {
        throw new HttpException('Invalid team performance structure.', HttpStatus.BAD_REQUEST);
      }
    }
  }

  validateTeamActivityLogs(teamActivityLogs: any[]) {
    if (teamActivityLogs) {
      const isValid = teamActivityLogs.every(log =>
        typeof log.date === 'string' && typeof log.activity === 'string'
      );

      if (!isValid) {
        throw new HttpException('Invalid team activity logs structure.', HttpStatus.BAD_REQUEST);
      }
    }
  }

  verifyToken(token: string) {
    return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
  }
  async createTeam(createTeamDto: CreateTeamDto, teamLeader: string) {
    const user = await this.prisma.user.findMany();
    const filterUser = user.filter(elem => elem.role === "manager");
  
    const teamData: any = {
      teamLeader,
      visualRepresentation: createTeamDto.visualRepresentation || "default value",
      members: {
        connect: createTeamDto.members.map(id => ({ id })),
      },
      subteam: {
        connect: filterUser.map(team => ({ id: team.id })),
      },
      status: "active",
      teamName: createTeamDto.teamName,
      region: createTeamDto.region,
      reportingLines: createTeamDto.reportingLines,
      teamPerformance: createTeamDto.teamPerformance,
      teamActivityLogs: createTeamDto.teamActivityLogs,
    };
  
    if (createTeamDto.teamDescription) {
      teamData.teamDescription = createTeamDto.teamDescription;
    }
  
    const newTeam = await this.prisma.teamManagement.create({
      data: teamData,
    });
  
    return newTeam; // Ensure this line returns the created team
  }
  

  async getAllTeams() {
    return await this.prisma.teamManagement.findMany({
      select: {
        id: true,
        teamName: true,
        teamDescription: true,
        region: true,
        members: {
          select: {
            id: true,
            userName: true,
            email: true,
          }
        },
      }
    });
  }

  async findTeamById(teamId: string) {
    return await this.prisma.teamManagement.findUnique({
      where: { id: teamId },
    });
  }

  async updateTeam(updateTeamDto: UpdateTeamDto) {
    const { teamId, members } = updateTeamDto;

    const membersToAdd = members?.add || [];
    const membersToRemove = members?.remove || [];

    await this.prisma.teamManagement.update({
      where: { id: teamId },
      data: {
        ...updateTeamDto,
        members: {
          connect: membersToAdd.map(id => ({ id })),
          disconnect: membersToRemove.map(id => ({ id })),
        }
      }
    });
  }

  async searchTeamById(id: string) {
    return await this.prisma.teamManagement.findUnique({
      where: { id },
      select: {
        id: true,
        teamName: true,
        teamDescription: true,
        region: true,
        members: {
          select: {
            id: true,
            userName: true,
            email: true,
          }
        }
      }
    });
  }

  async organizeTeamsByRegion(regionName: string) {
    return await this.prisma.teamManagement.findMany({
      where: { region: regionName },
      select: {
        id: true,
        teamName: true,
        teamDescription: true,
        region: true,
        members: {
          select: {
            id: true,
            userName: true,
            email: true,
          }
        }
      }
    });
  }

  async searchAndFilterTeams(dto: SearchAndFilterTeamsDto) {
    const { teamName, region, memberId, limit = 10, offset = 0 } = dto;

    const filterCriteria: any = {};

    if (teamName) {
      filterCriteria.teamName = { contains: teamName, mode: "insensitive" };
    }

    if (region) {
      filterCriteria.region = { contains: region, mode: "insensitive" };
    }

    if (memberId) {
      filterCriteria.members = {
        some: {
          id: memberId,
        },
      };
    }

    const teams = await this.prisma.teamManagement.findMany({
      where: filterCriteria,
      take: limit,
      skip: offset,
      select: {
        id: true,
        teamName: true,
        region: true,
        members: {
          select: {
            id: true,
            userName: true,
            email: true,
          },
        },
      },
    });

    const totalCount = await this.prisma.teamManagement.count({
      where: filterCriteria,
    });

    const pagination = {
      limit,
      offset,
      totalCount,
    };

    return { teams, pagination };
  }

  async getTeamPerformanceAndActivityLogs(id: string) {
    return await this.prisma.teamManagement.findUnique({
      where: { id },
      select: {
        teamPerformance: true,
        teamActivityLogs: true,
      },
    });
  }

  async getTeamHierarchy(teamId: string) {
    return await this.prisma.teamManagement.findUnique({
      where: { id: teamId },
      include: {
        subteam: true,
        members: true,
      }
    });
  }
}
