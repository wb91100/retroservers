import { PrismaClient } from '@prisma/client';
import multer from 'multer';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';

const prisma = new PrismaClient();

// Configuration Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(process.cwd(), 'uploads', 'members', req.params.memberId);
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    // Générer un nom de fichier unique
    const uniqueName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  // Types de fichiers autorisés
  const allowedTypes = [
    'image/jpeg',
    'image/png', 
    'image/gif',
    'application/pdf',
    'image/webp'
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Type de fichier non autorisé. Formats acceptés: JPEG, PNG, GIF, PDF, WebP'), false);
  }
};

export const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB max
  }
});

// API Documents
export const documentsAPI = {
  // Récupérer tous les documents d'un membre
  async getByMember(req, res) {
    try {
      const { memberId } = req.params;
      
      const documents = await prisma.memberDocument.findMany({
        where: { memberId },
        orderBy: { uploadedAt: 'desc' }
      });
      
      res.json(documents);
    } catch (error) {
      console.error('Erreur récupération documents:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  },

  // Upload d'un document
  async upload(req, res) {
    try {
      const { memberId } = req.params;
      const { documentType, expiryDate, notes } = req.body;
      
      if (!req.file) {
        return res.status(400).json({ error: 'Aucun fichier fourni' });
      }

      // Vérifier que le membre existe
      const member = await prisma.member.findUnique({
        where: { id: memberId }
      });
      
      if (!member) {
        return res.status(404).json({ error: 'Membre introuvable' });
      }

      // Créer l'entrée en base
      const document = await prisma.memberDocument.create({
        data: {
          memberId,
          documentType,
          fileName: req.file.originalname,
          filePath: req.file.path,
          fileSize: req.file.size,
          mimeType: req.file.mimetype,
          expiryDate: expiryDate ? new Date(expiryDate) : null,
          notes,
          uploadedBy: req.user?.id || 'system'
        }
      });

      res.status(201).json(document);
    } catch (error) {
      console.error('Erreur upload document:', error);
      res.status(500).json({ error: 'Erreur lors de l\'upload' });
    }
  },

  // Télécharger un document
  async download(req, res) {
    try {
      const { documentId } = req.params;
      
      const document = await prisma.memberDocument.findUnique({
        where: { id: documentId },
        include: { member: true }
      });
      
      if (!document) {
        return res.status(404).json({ error: 'Document introuvable' });
      }

      // Vérifier que le fichier existe
      try {
        await fs.access(document.filePath);
      } catch {
        return res.status(404).json({ error: 'Fichier non trouvé sur le disque' });
      }

      // Définir les headers pour le téléchargement
      res.setHeader('Content-Disposition', `attachment; filename="${document.fileName}"`);
      res.setHeader('Content-Type', document.mimeType);
      
      // Envoyer le fichier
      res.sendFile(path.resolve(document.filePath));
    } catch (error) {
      console.error('Erreur téléchargement document:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  },

  // Valider/rejeter un document
  async updateStatus(req, res) {
    try {
      const { documentId } = req.params;
      const { status, notes } = req.body;
      
      const document = await prisma.memberDocument.update({
        where: { id: documentId },
        data: {
          status,
          notes
        }
      });
      
      res.json(document);
    } catch (error) {
      console.error('Erreur mise à jour statut document:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  },

  // Supprimer un document
  async delete(req, res) {
    try {
      const { documentId } = req.params;
      
      const document = await prisma.memberDocument.findUnique({
        where: { id: documentId }
      });
      
      if (!document) {
        return res.status(404).json({ error: 'Document introuvable' });
      }

      // Supprimer le fichier du disque
      try {
        await fs.unlink(document.filePath);
      } catch (error) {
        console.warn('Impossible de supprimer le fichier:', error);
      }

      // Supprimer l'entrée en base
      await prisma.memberDocument.delete({
        where: { id: documentId }
      });
      
      res.json({ message: 'Document supprimé' });
    } catch (error) {
      console.error('Erreur suppression document:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  },

  // Récupérer les documents expirant bientôt
  async getExpiring(req, res) {
    try {
      const { days = 60 } = req.query;
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + parseInt(days));

      const documents = await prisma.memberDocument.findMany({
        where: {
          expiryDate: {
            lte: futureDate,
            gte: new Date()
          },
          status: 'APPROVED'
        },
        include: {
          member: {
            select: {
              memberNumber: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        },
        orderBy: { expiryDate: 'asc' }
      });
      
      res.json(documents);
    } catch (error) {
      console.error('Erreur récupération documents expirants:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
};