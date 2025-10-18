// Script pour patcher temporairement le serveur avec des logs de debug

const fs = require('fs');
const path = require('path');

const serverPath = path.join(__dirname, 'src', 'server.js');
let content = fs.readFileSync(serverPath, 'utf8');

// Ajouter des logs de debug aux endpoints d'upload
const galleryEndpoint = `app.post('/vehicles/:parc/gallery', requireAuth, uploadLarge.array('images', 10), async (req, res) => {
  console.log('🔍 Gallery upload debug:', {
    parc: req.params.parc,
    filesCount: req.files?.length || 0,
    hasDB: !!prisma,
    user: req.user?.username || 'unknown'
  });
  
  if (req.files?.length) {
    req.files.forEach((file, i) => {
      console.log(\`  File \${i}:\`, {
        fieldname: file.fieldname,
        originalname: file.originalname,
        mimetype: file.mimetype,
        size: file.size
      });
    });
  }
  
  if (!ensureDB(res)) return;
  try {`;

// Remplacer l'endpoint galerie existant
content = content.replace(
  /app\.post\('\/vehicles\/:parc\/gallery'[^{]*{/,
  galleryEndpoint
);

const backgroundEndpoint = `app.post('/vehicles/:parc/background', requireAuth, uploadLarge.single('image'), async (req, res) => {
  console.log('🔍 Background upload debug:', {
    parc: req.params.parc,
    hasFile: !!req.file,
    hasDB: !!prisma,
    user: req.user?.username || 'unknown'
  });
  
  if (req.file) {
    console.log('  File:', {
      fieldname: req.file.fieldname,
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size
    });
  }
  
  if (!ensureDB(res)) return;
  try {`;

// Remplacer l'endpoint background existant
content = content.replace(
  /app\.post\('\/vehicles\/:parc\/background'[^{]*{/,
  backgroundEndpoint
);

// Sauvegarder la version patchée
fs.writeFileSync(serverPath + '.debug', content);
console.log('✅ Debug patch created as server.js.debug');
console.log('🔧 To apply: mv src/server.js src/server.js.original && mv src/server.js.debug src/server.js');
console.log('🔙 To revert: mv src/server.js.original src/server.js');