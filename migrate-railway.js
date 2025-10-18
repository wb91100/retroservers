const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function migrateRailway() {
  console.log('🚀 Migration RétroReports pour Railway...\n');
  
  try {
    // 1. Vérifier la connexion
    console.log('1️⃣ Test connexion Railway...');
    await prisma.$connect();
    console.log('✅ Connecté à Railway PostgreSQL\n');

    // 2. Vérifier si les tables existent
    console.log('2️⃣ Vérification des tables...');
    try {
      const tables = await prisma.$queryRaw`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('retro_reports', 'retro_report_comments')
      `;
      console.log('📋 Tables trouvées:', tables);

      if (tables.length < 2) {
        console.log('⚠️ Tables manquantes. Lancement de la migration...');
        
        // Créer les tables si elles n'existent pas
        await prisma.$executeRaw`
          CREATE TABLE IF NOT EXISTS "retro_reports" (
            "id" TEXT NOT NULL,
            "title" TEXT NOT NULL,
            "description" TEXT NOT NULL,
            "category" TEXT,
            "priority" TEXT NOT NULL DEFAULT 'medium',
            "status" TEXT NOT NULL DEFAULT 'open',
            "type" TEXT NOT NULL DEFAULT 'bug',
            "assignedTo" TEXT,
            "createdBy" TEXT NOT NULL,
            "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
            "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT "retro_reports_pkey" PRIMARY KEY ("id")
          );
        `;
        
        await prisma.$executeRaw`
          CREATE TABLE IF NOT EXISTS "retro_report_comments" (
            "id" TEXT NOT NULL,
            "reportId" TEXT NOT NULL,
            "message" TEXT NOT NULL,
            "author" TEXT NOT NULL,
            "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT "retro_report_comments_pkey" PRIMARY KEY ("id"),
            CONSTRAINT "retro_report_comments_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "retro_reports"("id") ON DELETE CASCADE ON UPDATE CASCADE
          );
        `;
        
        console.log('✅ Tables créées sur Railway');
      } else {
        console.log('✅ Tables déjà présentes sur Railway');
      }
    } catch (e) {
      console.log('❌ Erreur vérification tables:', e.message);
    }

    // 3. Test de fonctionnement
    console.log('\n3️⃣ Test de fonctionnement...');
    
    const testReport = await prisma.retroReport.create({
      data: {
        title: 'Test Migration Railway',
        description: 'Test pour vérifier que la migration fonctionne sur Railway',
        category: 'Test',
        priority: 'low',
        type: 'other',
        status: 'open',
        createdBy: 'migration@railway.com'
      }
    });
    
    console.log('✅ Test report créé:', testReport.id);

    // Test commentaire
    const testComment = await prisma.retroReportComment.create({
      data: {
        reportId: testReport.id,
        message: 'Commentaire de test migration Railway',
        author: 'migration@railway.com'
      }
    });
    
    console.log('✅ Test commentaire créé:', testComment.id);

    // Nettoyage
    await prisma.retroReportComment.delete({ where: { id: testComment.id } });
    await prisma.retroReport.delete({ where: { id: testReport.id } });
    console.log('✅ Nettoyage terminé');

    console.log('\n🎉 Migration Railway terminée avec succès !');
    console.log('🚀 Le serveur Railway est prêt pour les RétroReports');

  } catch (error) {
    console.error('\n❌ Erreur migration Railway:', error);
    
    if (error.message.includes('connect')) {
      console.log('\n💡 Vérifiez:');
      console.log('   - La variable DATABASE_URL est correcte');
      console.log('   - La base PostgreSQL Railway est accessible');
    }
  } finally {
    await prisma.$disconnect();
  }
}

if (require.main === module) {
  migrateRailway()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

module.exports = { migrateRailway };