import 'dotenv/config';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

function humanize(key) {
  return key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, ' $1');
}
function toText(v) {
  if (v == null) return '';
  if (Array.isArray(v)) return v.map(toText).join(', ');
  if (typeof v === 'object') return Object.values(v).map(toText).join(', ');
  return String(v);
}

async function run() {
  const vehicles = await prisma.vehicle.findMany();
  let updatedCount = 0;

  for (const v of vehicles) {
    let parsed = [];
    try { parsed = v.caracteristiques ? JSON.parse(v.caracteristiques) : []; } catch {}
    let arrayified = [];

    if (Array.isArray(parsed)) {
      arrayified = parsed
        .filter(it => it && (it.label != null || it.value != null))
        .map(it => ({ label: toText(it.label), value: toText(it.value) }));
    } else if (parsed && typeof parsed === 'object') {
      arrayified = Object.entries(parsed)
        .filter(([k]) => k !== 'label' && k !== 'value')
        .map(([k, val]) => ({ label: humanize(k), value: toText(val) }));
    } else {
      arrayified = [];
    }

    // Dédup par label (garde la première valeur non vide)
    const seen = new Map();
    for (const it of arrayified) {
      const key = (it.label || '').trim().toLowerCase();
      if (!key) continue;
      if (!seen.has(key) || !seen.get(key)?.value) {
        seen.set(key, { label: it.label, value: it.value });
      }
    }
    const normalized = Array.from(seen.values());

    // Si changement, écrire
    const oldStr = v.caracteristiques || null;
    const newStr = normalized.length ? JSON.stringify(normalized) : null;
    if (oldStr !== newStr) {
      await prisma.vehicle.update({
        where: { id: v.id },
        data: { caracteristiques: newStr }
      });
      updatedCount++;
      console.log(`✅ ${v.parc}: ${normalized.length} caractéristiques normalisées`);
    }
  }

  console.log(`\n🎉 Terminé. ${updatedCount} véhicule(s) mis à jour.`);
}

run().finally(() => prisma.$disconnect());