import fetch from 'node-fetch';
import FormData from 'form-data';
import fs from 'fs';

const API_URL = 'https://attractive-kindness-rbe-serveurs.up.railway.app';

// Test avec un token valide (remplace par un vrai token)
const TEST_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // À remplacer

async function testUpload() {
  try {
    // Créer une image test très petite (1x1 pixel PNG)
    const testImageBuffer = Buffer.from([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
      0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
      0x54, 0x08, 0x57, 0x63, 0xF8, 0x0F, 0x00, 0x00,
      0x01, 0x00, 0x01, 0x5C, 0xC2, 0x8A, 0x58, 0x00,
      0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
      0x42, 0x60, 0x82
    ]);

    console.log('🧪 Testing gallery upload...');

    const formData = new FormData();
    formData.append('images', testImageBuffer, {
      filename: 'test.png',
      contentType: 'image/png'
    });

    const response = await fetch(`${API_URL}/vehicles/920/gallery`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TEST_TOKEN}`,
        ...formData.getHeaders()
      },
      body: formData
    });

    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers));

    const text = await response.text();
    console.log('Response body:', text);

    if (response.ok) {
      console.log('✅ Upload successful');
    } else {
      console.log('❌ Upload failed');
    }

  } catch (error) {
    console.error('❌ Test error:', error.message);
  }
}

console.log('🚀 Starting upload test...');
testUpload();