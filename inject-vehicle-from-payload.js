import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const prisma = new PrismaClient();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Utilitaires pour sérialiser proprement
const strOrNull = (v) => (v === undefined ? undefined : (v ?? null));
const dateOrNull = (v) => (v === undefined ? undefined : (v ? new Date(v) : null));
const jsonStrOrNull = (v) => (v === undefined ? undefined : (v == null ? null : JSON.stringify(v)));

async function run() {
  try {
    const payloadPath = path.join(__dirname, 'payload920.json'); // changeable si besoin
    const raw = fs.readFileSync(payloadPath, 'utf8');
    const p = JSON.parse(raw);

    if (!p.parc) throw new Error('payload.parc manquant');

    console.log(`🚗 Upsert véhicule ${p.parc} (non destructif) ...`);

    // Prépare les champs (uniquement ceux présents dans le payload)
    const base = {
      parc: p.parc,
      type: strOrNull(p.type),
      modele: strOrNull(p.modele),
      marque: strOrNull(p.marque),
      subtitle: strOrNull(p.subtitle),
      immat: strOrNull(p.immat),
      etat: strOrNull(p.etat),
      energie: strOrNull(p.energie),
      miseEnCirculation: dateOrNull(p.miseEnCirculation),
      description: strOrNull(p.description),
      history: strOrNull(p.history),
      caracteristiques: jsonStrOrNull(p.caracteristiques), // attend un tableau [{label,value}]
      gallery: jsonStrOrNull(p.gallery) // attend un tableau de strings (URLs relatives ok)
    };

    // Construction data create/update:
    const createData = {};
    const updateData = {};

    Object.entries(base).forEach(([key, val]) => {
      // create: si défini, on met la valeur; update: si défini, on met la valeur (sinon on ne touche pas)
      if (val !== undefined) {
        createData[key] = val;
        if (key !== 'parc') updateData[key] = val; // parc ne s’update pas
      }
    });

    const result = await prisma.vehicle.upsert({
      where: { parc: p.parc },
      create: createData,
      update: updateData
    });

    console.log(`✅ Véhicule upsert: ${result.parc} - ${result.marque} ${result.modele}`);
    // petite vérif lecture
    const verify = await prisma.vehicle.findUnique({ where: { parc: p.parc } });
    console.log('📋 Caractéristiques items:', (() => {
      try { return JSON.parse(verify.caracteristiques || '[]').length; } catch { return 0; }
    })());
    console.log('📸 Galerie items:', (() => {
      try { return JSON.parse(verify.gallery || '[]').length; } catch { return 0; }
    })());
  } catch (e) {
    console.error('❌ Erreur upsert:', e.message);
    process.exitCode = 1;
  } finally {
    await prisma.$disconnect();
  }
}

run();