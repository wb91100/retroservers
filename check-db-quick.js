const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function quickCheck() {
  console.log('🚀 Vérification rapide...\n');
  
  try {
    // Test connexion
    await prisma.$connect();
    console.log('✅ Connexion DB OK');

    // Test des tables
    try {
      const count = await prisma.retroReport.count();
      console.log(`✅ Table retro_reports OK (${count} entrées)`);
    } catch (e) {
      console.log('❌ Table retro_reports:', e.message);
      return;
    }

    // Test création ultra simple
    try {
      const test = await prisma.retroReport.create({
        data: {
          title: 'Test Quick',
          description: 'Test',
          createdBy: 'test'
        }
      });
      console.log('✅ Création OK, ID:', test.id);

      // Suppression du test
      await prisma.retroReport.delete({ where: { id: test.id } });
      console.log('✅ Suppression OK');

      console.log('\n🎉 Tout fonctionne !');

    } catch (createError) {
      console.log('❌ Erreur création:', createError.message);
      console.log('Code:', createError.code);
    }

  } catch (error) {
    console.log('❌ Erreur générale:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

quickCheck();