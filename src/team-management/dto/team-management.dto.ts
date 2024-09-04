import { IsString, IsNotEmpty, IsUUID, IsOptional } from 'class-validator';


export class CreateTeamDto {
  teamName: string;
  teamDescription: string;
  region: string;
  members: string[]; 
  visualRepresentation?: string;
  subteam: string[];
  teamLeader: string;
  reportingLines: string;
  teamPerformance: { metric: string; value: number }[]; // Corrected type
  teamActivityLogs: { date: string; activity: string }[]; // Corrected type
}

  
  export class UpdateTeamDto {
    teamId: string;
    teamName?: string;
    teamDescription?: string;
    region?: string;
    members?: {
      add?: string[];
      remove?: string[];
    };
  }
  
  export class SearchAndFilterTeamsDto {
    teamName: string;
    region: string;
    memberId: string;
    limit : number;
    offset: number
  }

  export class SearchTeamByIdDto {
    @IsUUID()
    @IsNotEmpty()
    id: string;
  }
  
  export class OrganizeTeamsByRegionDto {
    @IsString()
    @IsNotEmpty()
    regionName: string;
  }