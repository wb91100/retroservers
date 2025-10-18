const express = require('express');
const multer = require('multer');
const cors = require('cors');

const app = express();

// Enable CORS et logs
app.use(cors());
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, {
    headers: Object.keys(req.headers),
    contentType: req.get('Content-Type'),
    contentLength: req.get('Content-Length')
  });
  next();
});

// Multer config identique
const galleryStorage = multer.memoryStorage();
const uploadLarge = multer({ 
  storage: galleryStorage, 
  limits: { fileSize: 1.5 * 1024 * 1024 },
  onError: (err, next) => {
    console.error('Multer error:', err);
    next(err);
  }
});

// Test endpoint
app.post('/test-upload', (req, res, next) => {
  console.log('🔍 Before multer middleware');
  next();
}, uploadLarge.array('images', 10), (req, res) => {
  console.log('📁 Files received:', req.files?.length || 0);
  console.log('📝 Body:', req.body);
  
  if (req.files?.length) {
    req.files.forEach((file, i) => {
      console.log(`File ${i}:`, {
        fieldname: file.fieldname,
        originalname: file.originalname,
        mimetype: file.mimetype,
        size: file.size
      });
    });
  }
  
  res.json({ 
    success: true, 
    filesCount: req.files?.length || 0,
    gallery: ['test-image-1.jpg', 'test-image-2.jpg']
  });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('❌ Express error:', error);
  res.status(500).json({ 
    error: 'Upload failed', 
    message: error.message,
    code: error.code 
  });
});

const PORT = 4001;
app.listen(PORT, () => {
  console.log(`🧪 Debug server running on http://localhost:${PORT}`);
  console.log('Test upload: POST http://localhost:4001/test-upload');
});