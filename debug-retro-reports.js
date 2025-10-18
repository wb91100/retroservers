const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient({
  log: ['query', 'info', 'warn', 'error'],
});

async function debugRetroReports() {
  console.log('🔍 === DIAGNOSTIC RÉTRO REPORTS ===\n');

  try {
    // 1. Test connexion base
    console.log('1️⃣ Test de connexion...');
    await prisma.$connect();
    console.log('✅ Connexion OK\n');

    // 2. Vérification des tables
    console.log('2️⃣ Vérification des tables...');
    
    try {
      const result = await prisma.$queryRaw`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('retro_reports', 'retro_report_comments')
      `;
      console.log('📋 Tables trouvées:', result);
    } catch (e) {
      console.log('❌ Erreur vérification tables:', e.message);
    }

    // 3. Vérification schéma RetroReport
    console.log('\n3️⃣ Vérification schéma retro_reports...');
    try {
      const columns = await prisma.$queryRaw`
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns 
        WHERE table_name = 'retro_reports'
        ORDER BY ordinal_position
      `;
      console.log('📊 Colonnes retro_reports:');
      columns.forEach(col => {
        console.log(`   - ${col.column_name}: ${col.data_type} ${col.is_nullable === 'NO' ? '(NOT NULL)' : '(NULL)'}`);
      });
    } catch (e) {
      console.log('❌ Erreur schéma:', e.message);
    }

    // 4. Test de création simple
    console.log('\n4️⃣ Test de création simple...');
    
    const testData = {
      title: 'Test Diagnostic',
      description: 'Test de création pour diagnostic',
      category: 'Debug',
      priority: 'low',
      type: 'other',
      status: 'open',
      createdBy: 'debug@system.com'
    };
    
    console.log('📝 Données de test:', testData);
    
    try {
      const testReport = await prisma.retroReport.create({
        data: testData
      });
      console.log('✅ Création test réussie:', {
        id: testReport.id,
        title: testReport.title
      });

      // 5. Test de récupération
      console.log('\n5️⃣ Test de récupération...');
      const retrieved = await prisma.retroReport.findUnique({
        where: { id: testReport.id },
        include: { comments: true }
      });
      console.log('✅ Récupération OK:', !!retrieved);

      // 6. Nettoyage
      console.log('\n6️⃣ Nettoyage...');
      await prisma.retroReport.delete({
        where: { id: testReport.id }
      });
      console.log('✅ Nettoyage terminé');

    } catch (createError) {
      console.error('❌ Erreur création test:', createError);
      
      if (createError.code) {
        console.error('   Code Prisma:', createError.code);
        console.error('   Meta:', createError.meta);
      }
    }

    // 7. Comptage actuel
    console.log('\n7️⃣ État actuel...');
    const reportCount = await prisma.retroReport.count();
    const commentCount = await prisma.retroReportComment.count();
    console.log(`📊 Reports actuels: ${reportCount}`);
    console.log(`📊 Commentaires actuels: ${commentCount}`);

    console.log('\n🎉 Diagnostic terminé avec succès!');

  } catch (error) {
    console.error('\n❌ === ERREUR DIAGNOSTIC ===');
    console.error('Type:', error.constructor.name);
    console.error('Message:', error.message);
    console.error('Code:', error.code);
    console.error('Meta:', error.meta);
    
    if (error.message.includes('does not exist')) {
      console.log('\n💡 SOLUTION: Les tables n\'existent pas. Lancez:');
      console.log('   npx prisma migrate dev --name create-retro-reports');
      console.log('   npx prisma generate');
    } else if (error.message.includes('connect')) {
      console.log('\n💡 SOLUTION: Problème de connexion. Vérifiez:');
      console.log('   - La base de données est démarrée');
      console.log('   - DATABASE_URL dans .env');
      console.log('   - Les credentials de connexion');
    }

  } finally {
    await prisma.$disconnect();
  }
}

if (require.main === module) {
  debugRetroReports()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

module.exports = { debugRetroReports };