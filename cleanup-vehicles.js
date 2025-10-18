import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function cleanupVehicles() {
  console.log('🧹 Nettoyage des véhicules...');
  
  try {
    // Récupérer tous les véhicules
    const allVehicles = await prisma.vehicle.findMany({
      select: { parc: true, modele: true, marque: true }
    });
    
    console.log(`📋 Véhicules trouvés: ${allVehicles.length}`);
    allVehicles.forEach(v => console.log(`  - ${v.parc}: ${v.marque} ${v.modele}`));
    
    // Supprimer tous sauf le 920
    const result = await prisma.vehicle.deleteMany({
      where: {
        parc: {
          not: '920'
        }
      }
    });
    
    console.log(`🗑️  ${result.count} véhicules supprimés`);
    
    // Vérifier le résultat
    const remaining = await prisma.vehicle.findMany({
      select: { parc: true, modele: true, marque: true }
    });
    
    console.log(`✅ Véhicules restants: ${remaining.length}`);
    remaining.forEach(v => console.log(`  - ${v.parc}: ${v.marque} ${v.modele}`));
    
  } catch (error) {
    console.error('❌ Erreur nettoyage:', error.message);
  }
}

cleanupVehicles().finally(() => prisma.$disconnect());