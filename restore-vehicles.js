import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

// Tes véhicules (ajoute tous ceux que tu avais)
const vehicles = [
  {
    parc: '920',
    type: 'Bus',
    modele: 'Citaro ♿',
    marque: 'Mercedes-Benz',
    subtitle: 'Citaro 1 | € II | ❄️ | ♿',
    immat: 'FG-920-RE',
    etat: 'Préservé',
    energie: 'Diesel',
    miseEnCirculation: new Date('2001-07-01'),
    description: 'Bus urbain accessible, représentatif des débuts 2000.',
    history: 'Entré en service en juillet 2001. Ex-592/720/X/920 selon réaffectations internes. Préservé par l\'association après réforme.',
    caracteristiques: JSON.stringify({
      fleetNumbers: '592 / 720 / X / 920',
      constructeur: 'Mercedes-Benz',
      miseEnCirculationTexte: 'juillet 2001',
      longueur: '11,95 m',
      placesAssises: '32',
      placesDebout: '64',
      ufr: '1',
      preservePar: 'Association RétroBus Essonne',
      normeEuro: 'Euro II',
      moteur: 'Mercedes-Benz OM906hLA - 279 ch',
      boiteVitesses: 'Automatique ZF5HP-502C',
      nombrePortes: '2',
      livree: 'Grise',
      girouette: 'Duhamel LED Oranges + Pastilles Vertes',
      climatisation: 'Complète'
    })
  }
  // AJOUTE ICI tous tes autres véhicules avec le même format
];

async function restoreVehicles() {
  console.log('🚗 Restauration des véhicules...');
  
  for (const vehicle of vehicles) {
    try {
      const existing = await prisma.vehicle.findUnique({
        where: { parc: vehicle.parc }
      });
      
      if (existing) {
        console.log(`⏭️  ${vehicle.parc} existe déjà`);
        continue;
      }
      
      await prisma.vehicle.create({ data: vehicle });
      console.log(`✅ Créé: ${vehicle.parc} - ${vehicle.marque} ${vehicle.modele}`);
      
    } catch (error) {
      console.error(`❌ Erreur pour ${vehicle.parc}:`, error.message);
    }
  }
  
  console.log('🎉 Restauration terminée');
}

restoreVehicles().finally(() => prisma.$disconnect());