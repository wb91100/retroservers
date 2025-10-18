import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function setupMemberAccess() {
  console.log('🚀 Configuration du système d\'accès membres...');

  try {
    // 1. Créer la table des logs si elle n'existe pas
    console.log('📋 Vérification des tables...');
    
    // 2. Activer l'accès pour les membres actifs existants
    const activeMembers = await prisma.member.findMany({
      where: {
        membershipStatus: 'ACTIVE',
        loginEnabled: false
      }
    });

    console.log(`👥 ${activeMembers.length} membres actifs sans accès MyRBE trouvés`);

    for (const member of activeMembers) {
      const year = new Date().getFullYear();
      const random = Math.floor(Math.random() * 900) + 100;
      const matricule = `${year}-${String(random).padStart(3, '0')}`;
      
      // Générer mot de passe temporaire
      const tempPassword = Math.random().toString(36).slice(-8).toUpperCase();
      
      await prisma.member.update({
        where: { id: member.id },
        data: {
          matricule,
          temporaryPassword: tempPassword,
          loginEnabled: true,
          mustChangePassword: true,
          hasInternalAccess: true
        }
      });

      // Log de l'activation
      await prisma.connectionLog.create({
        data: {
          memberId: member.id,
          type: 'ACCOUNT_ENABLED',
          success: true,
          ipAddress: 'system',
          userAgent: 'setup-script',
          details: `Accès MyRBE activé automatiquement lors de la configuration initiale`
        }
      });

      console.log(`✅ Accès activé pour ${member.firstName} ${member.lastName} - Matricule: ${matricule} - Mot de passe: ${tempPassword}`);
    }

    // 3. Créer un rapport de configuration
    const stats = await prisma.member.groupBy({
      by: ['loginEnabled'],
      _count: true
    });

    console.log('\n📊 Rapport de configuration:');
    console.log('Membres avec accès MyRBE:', stats.find(s => s.loginEnabled)?._count || 0);
    console.log('Membres sans accès:', stats.find(s => !s.loginEnabled)?._count || 0);

    console.log('\n✅ Configuration terminée avec succès!');

  } catch (error) {
    console.error('❌ Erreur lors de la configuration:', error);
  } finally {
    await prisma.$disconnect();
  }
}

setupMemberAccess();