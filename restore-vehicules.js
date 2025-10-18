import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

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
    }),
    backgroundImage: '/assets/920_back.jpg',
    backgroundPosition: '50% 20%'
  },
  {
    parc: '456',
    type: 'Bus',
    modele: 'Agora Line',
    marque: 'Renault',
    subtitle: 'Agora Line | € III',
    immat: 'CD-456-EF',
    etat: 'En service',
    energie: 'Diesel',
    miseEnCirculation: new Date('2003-05-15'),
    description: 'Bus standard urbain.',
    history: 'Véhicule acquis en 2018.',
    caracteristiques: JSON.stringify({
      constructeur: 'Renault',
      longueur: '12,00 m',
      placesAssises: '28',
      placesDebout: '70'
    })
  },
  {
    parc: '789',
    type: 'Bus',
    modele: 'Citelis',
    marque: 'Irisbus',
    subtitle: 'Citelis | € IV | ❄️',
    immat: 'GH-789-IJ',
    etat: 'Disponible',
    energie: 'Diesel',
    miseEnCirculation: new Date('2008-09-20'),
    description: 'Bus moderne confortable.',
    history: 'Intégré à la collection en 2020.',
    caracteristiques: JSON.stringify({
      constructeur: 'Irisbus',
      longueur: '12,00 m',
      placesAssises: '30',
      placesDebout: '65'
    })
  }
];

async function restore() {
  console.log('🚗 Restauration des véhicules...');
  
  for (const vehicleData of vehicles) {
    try {
      const existing = await prisma.vehicle.findUnique({
        where: { parc: vehicleData.parc }
      });
      
      if (existing) {
        console.log(`⏭️  ${vehicleData.parc} existe déjà`);
        continue;
      }
      
      await prisma.vehicle.create({ data: vehicleData });
      console.log(`✅ Créé: ${vehicleData.parc} - ${vehicleData.marque} ${vehicleData.modele}`);
      
    } catch (error) {
      console.error(`❌ Erreur ${vehicleData.parc}:`, error.message);
    }
  }
  
  const total = await prisma.vehicle.count();
  console.log(`🎉 Terminé. Total: ${total} véhicules`);
}

restore().finally(() => prisma.$disconnect());