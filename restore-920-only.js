import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function restore920() {
  console.log('🚗 Restauration du véhicule 920...');
  
  try {
    // Vérifier si existe déjà
    const existing = await prisma.vehicle.findUnique({
      where: { parc: '920' }
    });
    
    if (existing) {
      console.log('⏭️  920 existe déjà');
      return;
    }
    
    // Créer le 920 (données exactes du seed.js)
    await prisma.vehicle.create({
      data: {
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
    });
    
    console.log('✅ 920 créé: Mercedes-Benz Citaro');
    
  } catch (error) {
    console.error('❌ Erreur 920:', error.message);
  }
  
  const total = await prisma.vehicle.count();
  console.log(`📊 Total véhicules: ${total}`);
}

restore920().finally(() => prisma.$disconnect());