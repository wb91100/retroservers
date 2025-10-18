-- Migration SQL à ajouter au schéma Prisma

-- Ajouter l'enum pour les rôles
CREATE TYPE "MemberRole" AS ENUM ('MEMBER', 'DRIVER', 'ADMIN', 'BUREAU');

-- Modifier la table Member pour ajouter les nouveaux champs
ALTER TABLE "Member" 
ADD COLUMN "role" "MemberRole" DEFAULT 'MEMBER',
ADD COLUMN "driverLicense" TEXT,
ADD COLUMN "licenseExpiryDate" TIMESTAMP(3),
ADD COLUMN "medicalCertificateDate" TIMESTAMP(3),
ADD COLUMN "emergencyContact" TEXT,
ADD COLUMN "emergencyPhone" TEXT,
ADD COLUMN "driverCertifications" TEXT[], -- Array de certifications
ADD COLUMN "vehicleAuthorizations" TEXT[], -- Array des véhicules autorisés
ADD COLUMN "maxPassengers" INTEGER,
ADD COLUMN "driverNotes" TEXT;

-- Créer des index pour les recherches
CREATE INDEX "Member_role_idx" ON "Member"("role");
CREATE INDEX "Member_licenseExpiryDate_idx" ON "Member"("licenseExpiryDate");