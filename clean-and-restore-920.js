import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

// Données du 920 depuis votre restore-vehicles.js
const vehicle920 = {
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
};

async function cleanAndRestore920() {
  console.log('🧹 Suppression de tous les véhicules...');
  
  try {
    // 1. Lister les véhicules existants
    const existing = await prisma.vehicle.findMany({
      select: { parc: true, modele: true, marque: true }
    });
    
    console.log(`📋 Véhicules actuels: ${existing.length}`);
    existing.forEach(v => console.log(`  - ${v.parc}: ${v.marque} ${v.modele}`));
    
    // 2. Supprimer TOUS les véhicules
    const deleteResult = await prisma.vehicle.deleteMany({});
    console.log(`🗑️  ${deleteResult.count} véhicules supprimés`);
    
    // 3. Restaurer le 920
    console.log('🚗 Restauration du véhicule 920...');
    
    const created = await prisma.vehicle.create({ 
      data: vehicle920 
    });
    
    console.log(`✅ Créé: ${created.parc} - ${created.marque} ${created.modele}`);
    
    // 4. Vérification finale
    const final = await prisma.vehicle.findMany({
      select: { parc: true, modele: true, marque: true }
    });
    
    console.log(`🎉 Véhicules finaux: ${final.length}`);
    final.forEach(v => console.log(`  ✓ ${v.parc}: ${v.marque} ${v.modele}`));
    
  } catch (error) {
    console.error('❌ Erreur:', error.message);
  }
}

cleanAndRestore920().finally(() => prisma.$disconnect());