import 'dotenv/config';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function initializeDB() {
  try {
    // Vérifier si la DB est accessible
    await prisma.$connect();
    console.log('✅ Base de données connectée');
    
    // Vérifier s'il y a des véhicules
    const vehicleCount = await prisma.vehicle.count();
    console.log(`📊 ${vehicleCount} véhicule(s) en base`);
    
  } catch (error) {
    console.error('❌ Erreur DB:', error);
  } finally {
    await prisma.$disconnect();
  }
}

initializeDB();