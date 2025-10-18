import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
  const exists = await prisma.vehicle.findUnique({ where: { parc: '920' } });
  if (exists) {
    console.log('Véhicule 920 déjà présent, seed ignoré.');
    return;
  }

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
      history: 'Entré en service en juillet 2001. Ex-592/720/X/920 selon réaffectations internes. Préservé par l’association après réforme.',
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

  console.log('Seed OK: véhicule 920 créé.');

  await prisma.event.upsert({
    where: { id: 'halloween2025' },
    update: {},
    create: {
      id: 'halloween2025',
      title: 'RétroWouh ! Halloween',
      date: new Date('2025-10-31T00:00:00Z'),
      time: '20:00',
      location: 'Salle des Fêtes de Villebon',
      description: 'Soirée spéciale Halloween avec animations, musique et surprises !',
      helloAssoUrl: 'https://www.helloasso.com/associations/rbe/evenements/halloween2025',
      adultPrice: 15,
      childPrice: 8,
      status: 'PUBLISHED',
      layout: 'default',
      extras: JSON.stringify({
        theme: 'Halloween',
        note: 'Costumes bienvenus'
      })
    }
  });

  console.log('✅ Seed event halloween2025 OK');
}

main()
  .catch(e => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());