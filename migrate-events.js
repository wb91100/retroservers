import { PrismaClient } from '@prisma/client';
import 'dotenv/config';

const prisma = new PrismaClient();

async function migrateEvents() {
  try {
    console.log('🔄 Migration de la table Event...');
    
    // Vérifier si la table existe et créer les colonnes manquantes
    try {
      // Test basique
      const count = await prisma.event.count();
      console.log(`✅ Table Event accessible avec ${count} événements`);
    } catch (error) {
      console.log('⚠️ Erreur table Event:', error.message);
      
      // Ajouter la colonne vehicleId si elle manque
      try {
        await prisma.$executeRaw`ALTER TABLE "Event" ADD COLUMN IF NOT EXISTS "vehicleId" TEXT;`;
        console.log('✅ Colonne vehicleId ajoutée');
      } catch (e) {
        console.log('Info vehicleId:', e.message);
      }
      
      // Modifier le type des colonnes prix si nécessaire
      try {
        await prisma.$executeRaw`ALTER TABLE "Event" ALTER COLUMN "adultPrice" TYPE DOUBLE PRECISION;`;
        await prisma.$executeRaw`ALTER TABLE "Event" ALTER COLUMN "childPrice" TYPE DOUBLE PRECISION;`;
        console.log('✅ Colonnes prix modifiées en DOUBLE PRECISION');
      } catch (e) {
        console.log('Info prix:', e.message);
      }
    }
    
    // Créer un événement de test s'il n'y en a pas
    const eventCount = await prisma.event.count();
    if (eventCount === 0) {
      console.log('📝 Création d\'un événement de test...');
      await prisma.event.create({
        data: {
          id: 'halloween2025',
          title: 'RétroWouh ! Halloween',
          date: new Date('2025-10-31T20:00:00Z'),
          time: '20:00',
          location: 'Salle des Fêtes de Villebon',
          description: 'Soirée spéciale Halloween avec animations, musique et surprises !',
          adultPrice: 15.0,
          childPrice: 8.0,
          helloAssoUrl: 'https://www.helloasso.com/associations/rbe/evenements/halloween2025',
          vehicleId: '920',
          status: 'PUBLISHED'
        }
      });
      console.log('✅ Événement de test créé');
    }
    
    // Lister les événements
    const events = await prisma.event.findMany();
    console.log('📋 Événements en base:', events.length);
    events.forEach(event => {
      console.log(`  - ${event.id}: ${event.title} (${event.status})`);
    });
    
    console.log('🎉 Migration terminée avec succès');
    
  } catch (error) {
    console.error('❌ Erreur de migration:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

migrateEvents();