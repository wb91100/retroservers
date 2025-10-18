const fetch = require('node-fetch');

const API_URL = process.env.API_URL || 'http://localhost:4000';

async function testRetroReportsAPI() {
  console.log('🧪 Test des API RétroReports...\n');

  try {
    // Test 1: Récupération des rapports
    console.log('1️⃣ Test GET /admin/retro-reports');
    const response = await fetch(`${API_URL}/admin/retro-reports`, {
      headers: {
        'Authorization': 'Bearer test-token', // Remplacer par un vrai token
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      const data = await response.json();
      console.log(`✅ Succès: ${data.reports?.length || 0} rapports récupérés`);
    } else {
      console.log(`❌ Échec: ${response.status} - ${response.statusText}`);
    }

    // Test 2: Création d'un nouveau rapport
    console.log('\n2️⃣ Test POST /admin/retro-reports');
    const newReport = {
      title: 'Test automatique RétroReports',
      description: 'Ceci est un test automatique du système RétroReports',
      category: 'Test',
      priority: 'low',
      type: 'other'
    };

    const createResponse = await fetch(`${API_URL}/admin/retro-reports`, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(newReport)
    });

    if (createResponse.ok) {
      const created = await createResponse.json();
      console.log(`✅ Succès: Rapport créé avec ID ${created.id}`);
      
      // Test 3: Ajout d'un commentaire
      console.log('\n3️⃣ Test POST /admin/retro-reports/:id/comments');
      const commentResponse = await fetch(`${API_URL}/admin/retro-reports/${created.id}/comments`, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: 'Test de commentaire automatique',
          status: 'in_progress'
        })
      });

      if (commentResponse.ok) {
        console.log('✅ Succès: Commentaire ajouté');
      } else {
        console.log(`❌ Échec commentaire: ${commentResponse.status}`);
      }

    } else {
      console.log(`❌ Échec création: ${createResponse.status}`);
    }

    console.log('\n🎉 Tests terminés !');

  } catch (error) {
    console.error('💥 Erreur lors des tests:', error.message);
  }
}

if (require.main === module) {
  testRetroReportsAPI();
}

module.exports = { testRetroReportsAPI };