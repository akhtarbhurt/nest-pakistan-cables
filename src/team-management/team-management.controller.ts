import { Controller, Get, Post, Put, Body, Param, Query, HttpException, HttpStatus, UseGuards, Req, SetMetadata } from '@nestjs/common';
import { TeamManagementService } from './team-management.service';
import { ApiResponse } from '../helper/common.helper';
// import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CreateTeamDto, UpdateTeamDto, SearchTeamByIdDto, OrganizeTeamsByRegionDto, SearchAndFilterTeamsDto } from './dto/team-management.dto';
import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { RolesGuard } from 'src/middleware/roleGuard.middleware';

@Controller('team-management')
export class TeamManagementController {
  constructor(private readonly teamManagementService: TeamManagementService) {}

  @Post('create')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
  async createTeam(@Body() createTeamDto: CreateTeamDto, @Req() req: Request) {
    const user = await this.teamManagementService.validateMembers(createTeamDto.members);
    if (user.length !== createTeamDto.members.length) {
      throw new HttpException('One or more members are invalid.', HttpStatus.BAD_REQUEST);
    }

    // Validate team performance
    this.teamManagementService.validateTeamPerformance(createTeamDto.teamPerformance);

    // Validate team activity logs
    this.teamManagementService.validateTeamActivityLogs(createTeamDto.teamActivityLogs);

    const token = req.cookies.accessToken;
    const decoded   = this.teamManagementService.verifyToken(token) as JwtPayload;

    const newTeam = await this.teamManagementService.createTeam(createTeamDto, decoded.userName );

    

    return new ApiResponse(201, { teamId: newTeam.id }, "Team created successfully");
  }

  @Get('all')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
  async getTeam() {
    const payload = await this.teamManagementService.getAllTeams();
    return new ApiResponse(200, payload, "Successfully retrieved teams");
  }

  @Put('update')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
  async updateTeam(@Body() updateTeamDto: UpdateTeamDto) {
    const existingTeam = await this.teamManagementService.findTeamById(updateTeamDto.teamId);
    if (!existingTeam) {
      throw new HttpException('Team not found.', HttpStatus.NOT_FOUND);
    }

    await this.teamManagementService.updateTeam(updateTeamDto);

    return new ApiResponse(200, {}, "Team updated successfully");
  }

  @Get(':id')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
  async searchTeamById(@Param() searchTeamByIdDto: SearchTeamByIdDto) {
    const team = await this.teamManagementService.searchTeamById(searchTeamByIdDto.id);
    if (!team) {
      throw new HttpException('No team exists with this ID', HttpStatus.NOT_FOUND);
    }

    return new ApiResponse(200, team, "Team retrieved successfully");
  }

  @Get('organize/region')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
  async organizeTeamsByRegion(@Query() organizeTeamsByRegionDto: OrganizeTeamsByRegionDto) {
    const teams = await this.teamManagementService.organizeTeamsByRegion(organizeTeamsByRegionDto.regionName);
    if (teams.length === 0) {
      throw new HttpException('No teams found matching the criteria.', HttpStatus.NOT_FOUND);
    }

    return new ApiResponse(200, teams, `Teams in region ${organizeTeamsByRegionDto.regionName} retrieved successfully`);
  }

  @Get('search-filter')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
  async searchAndFilterTeams(@Query() searchAndFilterTeamsDto: SearchAndFilterTeamsDto) {
    const { teams, pagination } = await this.teamManagementService.searchAndFilterTeams(searchAndFilterTeamsDto);

    if (teams.length === 0) {
      throw new HttpException('No teams found matching the criteria.', HttpStatus.NOT_FOUND);
    }

    return new ApiResponse(200, { teams, pagination }, "Teams retrieved successfully");
  }

  @Get('performance-reporting/:id')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
async performanceReporting(@Param('id') id: string) {
  const payload = await this.teamManagementService.getTeamPerformanceAndActivityLogs(id);
  
  if (payload.teamPerformance.length === 0 && payload.teamActivityLogs.length === 0) {
    throw new HttpException('No data found in database', HttpStatus.NOT_FOUND);
  }

  return new ApiResponse(200, payload, "Data retrieved successfully");
}


  @Get('hierarchy/:teamId')
  @SetMetadata('roles', ['superadmin', 'manager'])
  @UseGuards(RolesGuard)
  async teamHierarchyView(@Param('teamId') teamId: string) {
    const team = await this.teamManagementService.getTeamHierarchy(teamId);
    if (!team) {
      throw new HttpException('Team not found.', HttpStatus.NOT_FOUND);
    }

    return new ApiResponse(200, team, "Team hierarchy retrieved successfully");
  }
}

//me masjido me karta ho safar k doran