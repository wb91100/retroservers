const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function setupRetroReports() {
  try {
    console.log('🚀 Configuration du système RétroReportings...');

    // 1. Nettoyage des données existantes (optionnel)
    console.log('📝 Nettoyage des données existantes...');
    await prisma.retroReportComment.deleteMany({});
    await prisma.retroReport.deleteMany({});

    // 2. Création des tickets de test et d'exemple
    console.log('🎫 Création des tickets d\'exemple...');

    const sampleReports = [
      {
        title: 'Problème de connexion base de données',
        description: 'La connexion à la base de données se ferme parfois de manière inattendue lors des opérations longues sur les membres.',
        category: 'Technique',
        priority: 'high',
        type: 'bug',
        status: 'open',
        createdBy: 'w.belaidi@retrobus-essonne.fr',
      },
      {
        title: 'Amélioration interface gestion membres',
        description: 'L\'interface de gestion des membres nécessite une refonte complète pour améliorer l\'expérience utilisateur.',
        category: 'Interface',
        priority: 'critical',
        type: 'feature',
        status: 'open',
        createdBy: 'system@retrobus-essonne.fr',
      },
      {
        title: 'Optimisation des requêtes véhicules',
        description: 'Les requêtes sur la table des véhicules sont lentes avec plus de 1000 entrées.',
        category: 'Performance',
        priority: 'medium',
        type: 'performance',
        status: 'in_progress',
        createdBy: 'admin@retrobus-essonne.fr',
      },
      {
        title: 'Mise à jour sécurité JWT',
        description: 'Les tokens JWT doivent être mis à jour vers une version plus sécurisée.',
        category: 'Sécurité',
        priority: 'high',
        type: 'security',
        status: 'open',
        createdBy: 'security@retrobus-essonne.fr',
      },
      {
        title: 'Documentation API manquante',
        description: 'Il manque la documentation complète pour les endpoints de l\'API membres.',
        category: 'Documentation',
        priority: 'low',
        type: 'other',
        status: 'resolved',
        createdBy: 'doc@retrobus-essonne.fr',
      }
    ];

    const createdReports = [];
    for (const report of sampleReports) {
      const created = await prisma.retroReport.create({
        data: report
      });
      createdReports.push(created);
      console.log(`✅ Ticket créé: ${created.title}`);
    }

    // 3. Ajout de commentaires d'exemple
    console.log('💬 Ajout des commentaires d\'exemple...');
    
    // Commentaire sur le premier ticket
    await prisma.retroReportComment.create({
      data: {
        reportId: createdReports[0].id,
        message: 'J\'ai identifié que le problème vient du timeout de connexion configuré trop bas. Investigation en cours.',
        author: 'dev@retrobus-essonne.fr'
      }
    });

    // Commentaire sur le deuxième ticket
    await prisma.retroReportComment.create({
      data: {
        reportId: createdReports[1].id,
        message: 'Analyse UX terminée. Proposition de maquettes prête pour validation.',
        author: 'ux@retrobus-essonne.fr'
      }
    });

    // Mise à jour du statut du troisième ticket
    await prisma.retroReportComment.create({
      data: {
        reportId: createdReports[2].id,
        message: 'Optimisation terminée. Performance améliorée de 70%. Tests en cours.',
        author: 'performance@retrobus-essonne.fr'
      }
    });

    // Résolution du cinquième ticket
    await prisma.retroReportComment.create({
      data: {
        reportId: createdReports[4].id,
        message: 'Documentation complétée et publiée sur le wiki interne.',
        author: 'doc@retrobus-essonne.fr'
      }
    });

    console.log('🎉 Configuration RétroReportings terminée avec succès !');
    console.log(`📊 ${createdReports.length} tickets créés`);
    console.log('📝 4 commentaires ajoutés');
    
    console.log('\n🔗 Accès au système :');
    console.log('- URL: http://localhost:3000/admin/administrative');
    console.log('- Dashboard MyRBE: Carte "Gestion Administrative"');
    
    console.log('\n📋 Tickets créés :');
    createdReports.forEach((report, index) => {
      console.log(`${index + 1}. [${report.priority.toUpperCase()}] ${report.title} - ${report.status}`);
    });

  } catch (error) {
    console.error('❌ Erreur lors de la configuration:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Exécuter si appelé directement
if (require.main === module) {
  setupRetroReports()
    .then(() => {
      console.log('\n✨ Configuration terminée. Vous pouvez maintenant utiliser RétroReportings !');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Échec de la configuration:', error);
      process.exit(1);
    });
}

module.exports = { setupRetroReports };