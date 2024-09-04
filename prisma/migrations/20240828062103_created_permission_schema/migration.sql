-- CreateTable
CREATE TABLE "User" (
    "id" UUID NOT NULL,
    "userName" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "position" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "resetPasswordToken" TEXT,
    "resetPasswordExpires" TIMESTAMP(3),
    "tokenExpiry" TIMESTAMP(3),
    "deviceTypes" JSONB[] DEFAULT ARRAY[]::JSONB[],
    "unrecognizedBrowser" TEXT,
    "loginAttempt" TEXT,
    "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "mfaSecret" TEXT,
    "otpCode" TEXT,
    "otpExpiry" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "otpSentAt" TIMESTAMP(3),

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Permissions" (
    "id" UUID NOT NULL,
    "permission" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Permissions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Role" (
    "id" UUID NOT NULL,
    "roleName" TEXT NOT NULL,
    "assignPermissions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "userId" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" TEXT NOT NULL DEFAULT 'active',

    CONSTRAINT "Role_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TeamManagement" (
    "id" UUID NOT NULL,
    "teamName" TEXT NOT NULL,
    "teamDescription" TEXT NOT NULL,
    "region" TEXT NOT NULL,
    "visualRepresentation" TEXT NOT NULL,
    "teamLeader" TEXT NOT NULL,
    "reportingLines" TEXT NOT NULL,
    "teamPerformance" JSONB[],
    "teamActivityLogs" JSONB[],
    "status" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TeamManagement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_UserTeam" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_UserTeams" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "Permissions_id_idx" ON "Permissions"("id");

-- CreateIndex
CREATE INDEX "Role_id_idx" ON "Role"("id");

-- CreateIndex
CREATE INDEX "TeamManagement_id_idx" ON "TeamManagement"("id");

-- CreateIndex
CREATE UNIQUE INDEX "_UserTeam_AB_unique" ON "_UserTeam"("A", "B");

-- CreateIndex
CREATE INDEX "_UserTeam_B_index" ON "_UserTeam"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_UserTeams_AB_unique" ON "_UserTeams"("A", "B");

-- CreateIndex
CREATE INDEX "_UserTeams_B_index" ON "_UserTeams"("B");

-- AddForeignKey
ALTER TABLE "Role" ADD CONSTRAINT "Role_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_UserTeam" ADD CONSTRAINT "_UserTeam_A_fkey" FOREIGN KEY ("A") REFERENCES "TeamManagement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_UserTeam" ADD CONSTRAINT "_UserTeam_B_fkey" FOREIGN KEY ("B") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_UserTeams" ADD CONSTRAINT "_UserTeams_A_fkey" FOREIGN KEY ("A") REFERENCES "TeamManagement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_UserTeams" ADD CONSTRAINT "_UserTeams_B_fkey" FOREIGN KEY ("B") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
