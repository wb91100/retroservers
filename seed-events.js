import { PrismaClient } from '@prisma/client';
import 'dotenv/config';

const prisma = new PrismaClient();

async function seedEvents() {
  try {
    console.log('🌱 Création des événements de test...');
    
    // Vérifier si l'événement Halloween existe déjà
    const existingHalloween = await prisma.event.findUnique({
      where: { id: 'halloween2025' }
    });
    
    if (!existingHalloween) {
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
      console.log('✅ Événement Halloween créé');
    } else {
      console.log('ℹ️ Événement Halloween existe déjà');
    }
    
    // Créer un deuxième événement de test
    const existingNoel = await prisma.event.findUnique({
      where: { id: 'noel2025' }
    });
    
    if (!existingNoel) {
      await prisma.event.create({
        data: {
          id: 'noel2025',
          title: 'Marché de Noël RBE',
          date: new Date('2025-12-15T14:00:00Z'),
          time: '14:00',
          location: 'Place du Village - Villebon',
          description: 'Marché de Noël avec présentation de véhicules historiques et vente de produits artisanaux.',
          adultPrice: 5.0,
          childPrice: 0.0,
          helloAssoUrl: '',
          vehicleId: '920',
          status: 'DRAFT'
        }
      });
      console.log('✅ Événement Noël créé');
    } else {
      console.log('ℹ️ Événement Noël existe déjà');
    }
    
    // Lister tous les événements
    const events = await prisma.event.findMany({
      orderBy: { date: 'asc' }
    });
    
    console.log(`\n📋 Événements en base (${events.length}) :`);
    events.forEach(event => {
      const status = event.status === 'PUBLISHED' ? '🟢' : '🟡';
      console.log(`  ${status} ${event.id}: ${event.title} (${event.date.toISOString().split('T')[0]})`);
    });
    
    console.log('\n🎉 Événements de test créés avec succès !');
    
  } catch (error) {
    console.error('❌ Erreur lors de la création des événements:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

seedEvents();