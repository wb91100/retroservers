import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const prisma = new PrismaClient();

async function inject920() {
  console.log('🚗 Injection du véhicule 920 depuis payload920.json...');
  
  try {
    // 1. Lire le fichier JSON
    const jsonPath = path.join(__dirname, 'payload920.json');
    const rawData = fs.readFileSync(jsonPath, 'utf8');
    const payload = JSON.parse(rawData);
    
    console.log(`📄 Payload chargé: ${payload.parc} - ${payload.marque} ${payload.modele}`);
    
    // 2. Supprimer tous les véhicules existants
    const deleteResult = await prisma.vehicle.deleteMany({});
    console.log(`🗑️  ${deleteResult.count} véhicules supprimés`);
    
    // 3. Transformer les caractéristiques vers le format attendu par le serveur
    // Le serveur s'attend à un objet, pas un tableau label/value
    const caracteristiquesObj = {};
    payload.caracteristiques.forEach(item => {
      // Convertir les labels en clés utilisables
      const key = item.label
        .toLowerCase()
        .replace(/é/g, 'e')
        .replace(/è/g, 'e')
        .replace(/ê/g, 'e')
        .replace(/à/g, 'a')
        .replace(/ô/g, 'o')
        .replace(/î/g, 'i')
        .replace(/[^a-z0-9]/g, '')
        .replace(/^(.{1})/, (_, first) => first.toUpperCase())
        .replace(/([a-z])([A-Z])/g, '$1$2');
      
      caracteristiquesObj[key] = item.value;
    });

    // 4. Transformer les données pour Prisma
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
      caracteristiques: JSON.stringify(caracteristiquesObj), // Objet, pas tableau
      gallery: JSON.stringify(payload.gallery)
    };
    
    console.log('🔧 Caractéristiques transformées:', Object.keys(caracteristiquesObj));
    
    // 5. Créer le véhicule
    const created = await prisma.vehicle.create({ 
      data: vehicleData 
    });
    
    console.log(`✅ Véhicule créé: ${created.parc} - ${created.marque} ${created.modele}`);
    console.log(`📋 Caractéristiques: ${Object.keys(caracteristiquesObj).length} items`);
    console.log(`📸 Galerie: ${payload.gallery.length} photos`);
    
    // 6. Test de lecture pour vérifier la transformation
    const testRead = await prisma.vehicle.findUnique({
      where: { parc: '920' }
    });
    
    const parsedCaract = JSON.parse(testRead.caracteristiques || '{}');
    console.log('🧪 Test lecture caractéristiques:', Object.keys(parsedCaract).length, 'clés');
    
  } catch (error) {
    console.error('❌ Erreur injection:', error.message);
    console.error(error);
  }
}

inject920().finally(() => prisma.$disconnect());