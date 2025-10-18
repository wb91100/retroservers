import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function enableMyRBEForExistingMembers() {
  console.log('🔧 Activation de l\'accès MyRBE pour les membres existants...');
  
  // Récupérer tous les membres actifs sans accès MyRBE
  const members = await prisma.member.findMany({
    where: {
      membershipStatus: 'ACTIVE',
      loginEnabled: false
    }
  });
  
  console.log(`📋 ${members.length} membres à traiter`);
  
  for (const member of members) {
    const year = new Date().getFullYear();
    const random = Math.floor(Math.random() * 900) + 100;
    const matricule = `${year}-${random}`;
    
    // Générer mot de passe temporaire
    const tempPassword = Math.random().toString(36).slice(-8).toUpperCase();
    
    await prisma.member.update({
      where: { id: member.id },
      data: {
        matricule,
        temporaryPassword: tempPassword,
        loginEnabled: true,
        mustChangePassword: true
      }
    });
    
    console.log(`✅ ${member.firstName} ${member.lastName}: ${matricule} / ${tempPassword}`);
  }
  
  console.log('🎉 Activation terminée !');
  await prisma.$disconnect();
}

enableMyRBEForExistingMembers().catch(console.error);