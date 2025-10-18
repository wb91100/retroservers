import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const prisma = new PrismaClient();

async function inject920Fixed() {
  console.log('🚗 Injection CORRIGÉE du véhicule 920...');
  
  try {
    // 1. Lire le fichier JSON
    const jsonPath = path.join(__dirname, 'payload920.json');
    const rawData = fs.readFileSync(jsonPath, 'utf8');
    const payload = JSON.parse(rawData);
    
    console.log(`📄 Payload chargé: ${payload.parc} - ${payload.marque} ${payload.modele}`);
    
    // 2. Supprimer tous les véhicules existants
    const deleteResult = await prisma.vehicle.deleteMany({});
    console.log(`🗑️  ${deleteResult.count} véhicules supprimés`);
    
    // 3. ✅ GARDER LE FORMAT ORIGINAL - pas de transformation
    const vehicleData = {
      parc: payload.parc,
      type: payload.type,
      modele: payload.modele,
      marque: payload.marque,
      subtitle: payload.subtitle,
      immat: payload.immat,
      etat: payload.etat,
      energie: payload.energie,
      miseEnCirculation: new Date(payload.miseEnCirculation),
      description: payload.description,
      history: payload.history,
      // ✅ Format label/value ORIGINAL du JSON
      caracteristiques: JSON.stringify(payload.caracteristiques),
      gallery: JSON.stringify(payload.gallery)
    };
    
    console.log('🔧 Format caractéristiques:', payload.caracteristiques[0]);
    console.log('📸 Galerie:', payload.gallery);
    
    // 4. Créer le véhicule
    const created = await prisma.vehicle.create({ 
      data: vehicleData 
    });
    
    console.log(`✅ Véhicule créé: ${created.parc} - ${created.marque} ${created.modele}`);
    
    // 5. Test de lecture immédiate
    const testVehicle = await prisma.vehicle.findUnique({
      where: { parc: '920' }
    });
    
    console.log('\n📋 VÉRIFICATION:');
    console.log('Caractéristiques stockées:', JSON.parse(testVehicle.caracteristiques).length, 'items');
    console.log('Premier élément:', JSON.parse(testVehicle.caracteristiques)[0]);
    console.log('Galerie stockée:', JSON.parse(testVehicle.gallery || '[]').length, 'photos');
    console.log('Première photo:', JSON.parse(testVehicle.gallery || '[]')[0]);
    
  } catch (error) {
    console.error('❌ Erreur injection:', error.message);
    console.error(error.stack);
  }
}

inject920Fixed().finally(() => prisma.$disconnect());