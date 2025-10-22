// Load env early
import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import QRCode from 'qrcode';

// ---------------- Paths / App ----------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;
app.set('trust proxy', 1);

// ---------------- Uploads ----------------
const galleryUploadDir = path.join(__dirname, '../uploads/vehicles');
fs.mkdirSync(galleryUploadDir, { recursive: true });

const storage = multer.memoryStorage();
const uploadGallery = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// ---------------- Routers locaux ----------------
import finance from './finance.js';
app.use('/api/finance', finance);

// Local modules (si utilisés ailleurs)
import { documentsAPI as docsAPI, upload as documentsUpload } from './documents.js';
import * as newsletterService from './newsletter-service.js';

// ---------------- SMTP (optionnel) ----------------
const mailer = (process.env.SMTP_HOST && process.env.SMTP_USER)
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    })
  : null;

// ---------------- CORS (dynamic + credentials-safe) ----------------
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  const isAllowed = origin && (allowed.length === 0 || allowed.includes(origin));

  if (isAllowed && origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');

  const reqHeaders = req.headers['access-control-request-headers'];
  res.setHeader(
    'Access-Control-Allow-Headers',
    reqHeaders || 'Content-Type, Authorization, X-Requested-With, Accept'
  );

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  return next();
});

// ---------------- Parsers ----------------
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// ---------------- Prisma / Auth helpers ----------------
const prisma = new PrismaClient();
const AUTH_SECRET = process.env.AUTH_SECRET || 'dev_insecure_secret';

function verifyToken(token) {
  return jwt.verify(token, AUTH_SECRET);
}

function issueToken(payload, opts = {}) {
  return jwt.sign(payload, AUTH_SECRET, { expiresIn: opts.expiresIn || '7d' });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  try {
    const decoded = verifyToken(auth.slice(7));
    req.user = decoded;
    req.userId = decoded.userId || decoded.sub || decoded.id || null;
    req.userEmail = decoded.email || decoded.username || decoded.login || null;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function ensureDB(res) {
  if (!prisma) {
    res.status(503).json({ error: 'Base de données indisponible' });
    return false;
  }
  return true;
}

async function hashPassword(plain) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(plain, salt);
}

async function verifyPassword(plain, stored) {
  if (!stored) return false;
  if (stored.startsWith('$2')) return bcrypt.compare(plain, stored); // bcrypt hash
  return plain === stored; // fallback clair (mot de passe temporaire)
}

function parseJsonField(v) {
  if (v == null) return null;
  try { return JSON.parse(v); } catch { return null; }
}

function stringifyJsonField(v) {
  if (v == null) return null;
  try { return JSON.stringify(v); } catch { return null; }
}

function absolutize(u) { return u; } // hook futur si CDN

// ---------------- Admin users via ENV ----------------
let USERS = {};
try {
  USERS = JSON.parse(process.env.ADMIN_USERS || '{}');
} catch {
  USERS = {};
}

// ---------------- Utils Transform ----------------
function toText(v) {
  if (v == null) return '';
  if (Array.isArray(v)) return v.map(toText).join(', ');
  if (typeof v === 'object') return Object.values(v).map(toText).join(', ');
  return String(v);
}

const transformVehicle = (vehicle) => {
  if (!vehicle) return null;
  let caract = [];
  try {
    const parsed = vehicle.caracteristiques ? JSON.parse(vehicle.caracteristiques) : [];

    if (Array.isArray(parsed)) {
      caract = parsed
        .filter(it => it && (it.label != null || it.value != null))
        .map(it => ({ label: toText(it.label), value: toText(it.value) }));
    } else if (typeof parsed === 'object' && parsed) {
      caract = Object.entries(parsed)
        .filter(([key]) => key !== 'label' && key !== 'value')
        .map(([key, value]) => ({
          label: key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, ' $1'),
          value: toText(value)
        }));
    }
  } catch {
    caract = [];
  }

  const gallery = parseJsonField(vehicle.gallery) || [];
  return {
    id: vehicle.id,
    parc: vehicle.parc,
    type: vehicle.type,
    modele: vehicle.modele,
    marque: vehicle.marque,
    subtitle: vehicle.subtitle,
    immat: vehicle.immat,
    etat: vehicle.etat,
    miseEnCirculation: vehicle.miseEnCirculation,
    energie: vehicle.energie,
    description: vehicle.description,
    history: vehicle.history,
    backgroundImage: absolutize(vehicle.backgroundImage),
    backgroundPosition: vehicle.backgroundPosition,
    gallery: gallery.map(absolutize),
    caracteristiques: caract
  };
};

const transformEvent = (evt) => {
  if (!evt) return null;
  return {
    id: evt.id,
    title: evt.title,
    date: evt.date,
    time: evt.time,
    location: evt.location,
    description: evt.description,
    helloAssoUrl: evt.helloAssoUrl,
    adultPrice: evt.adultPrice,
    childPrice: evt.childPrice,
    vehicleId: evt.vehicleId,
    status: evt.status,
    layout: evt.layout,
    extras: evt.extras,
    createdAt: evt.createdAt,
    updatedAt: evt.updatedAt
  };
};

const transformStock = (s) => (s ? {
  id: s.id,
  reference: s.reference,
  name: s.name,
  description: s.description,
  category: s.category,
  subcategory: s.subcategory,
  quantity: s.quantity,
  minQuantity: s.minQuantity,
  unit: s.unit,
  location: s.location,
  supplier: s.supplier,
  purchasePrice: s.purchasePrice,
  salePrice: s.salePrice,
  status: s.status,
  lastRestockDate: s.lastRestockDate,
  expiryDate: s.expiryDate,
  notes: s.notes,
  createdBy: s.createdBy,
  createdAt: s.createdAt,
  updatedAt: s.updatedAt
} : null);

// ---------------- Health / Ping ----------------
app.get('/health', async (_req, res) => {
  let db = 'down';
  if (prisma) {
    try { await prisma.$queryRaw`SELECT 1`; db = 'up'; } catch { db = 'down'; }
  }
  res.json({ status: 'ok', port: PORT, db });
});

app.get('/public/health', async (_req, res) => {
  let db = 'down';
  if (prisma) {
    try { await prisma.$queryRaw`SELECT 1`; db = 'up'; } catch { db = 'down'; }
  }
  res.json({ status: 'ok', port: PORT, db });
});

app.get('/public/ping', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// ---------------- AUTH ----------------
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username & password requis' });
  }
  const uname = String(username).trim().toLowerCase();

  // 1) comptes ADMIN_USERS (ENV)
  const admin = USERS[uname];
  if (admin && admin.password === password) {
    const token = issueToken({
      sub: `admin:${uname}`,
      prenom: admin.prenom,
      nom: admin.nom,
      roles: admin.roles,
      type: 'admin'
    });
    return res.json({
      token,
      user: {
        id: `admin:${uname}`,
        username: uname,
        prenom: admin.prenom,
        nom: admin.nom,
        roles: admin.roles,
        type: 'admin'
      }
    });
  }

  // 2) Fallback: SiteUser DB
  if (!prisma) return res.status(401).json({ error: 'Identifiants invalides' });

  try {
    const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const siteUser = await prisma.siteUser.findFirst({
      where: { username: { equals: uname, mode: 'insensitive' } }
    });

    if (!siteUser) {
      await prisma.accessLog.create({
        data: {
          action: 'LOGIN_FAILED',
          success: false,
          ipAddress: clientIP,
          userAgent,
          details: `Utilisateur inexistant: ${uname}`
        }
      });
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    if (!siteUser.isActive) {
      await prisma.accessLog.create({
        data: {
          siteUserId: siteUser.id,
          action: 'LOGIN_FAILED',
          success: false,
          ipAddress: clientIP,
          userAgent,
          details: `Compte désactivé`
        }
      });
      return res.status(403).json({ error: 'Compte désactivé' });
    }

    if (!siteUser.hasInternalAccess) {
      await prisma.accessLog.create({
        data: {
          siteUserId: siteUser.id,
          action: 'LOGIN_FAILED',
          success: false,
          ipAddress: clientIP,
          userAgent,
          details: `Accès interne non autorisé`
        }
      });
      return res.status(403).json({ error: 'Accès intranet non autorisé' });
    }

    const ok = await bcrypt.compare(password, siteUser.password);
    if (!ok) {
      await prisma.accessLog.create({
        data: {
          siteUserId: siteUser.id,
          action: 'LOGIN_FAILED',
          success: false,
          ipAddress: clientIP,
          userAgent,
          details: `Mot de passe incorrect`
        }
      });
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    await prisma.siteUser.update({
      where: { id: siteUser.id },
      data: { lastLoginAt: new Date() }
    });

    await prisma.accessLog.create({
      data: {
        siteUserId: siteUser.id,
        action: 'LOGIN_SUCCESS',
        success: true,
        ipAddress: clientIP,
        userAgent,
        performedBy: siteUser.username,
        details: `Connexion réussie`
      }
    });

    const token = issueToken({
      sub: siteUser.id,
      username: siteUser.username,
      firstName: siteUser.firstName,
      lastName: siteUser.lastName,
      role: siteUser.role,
      internal: siteUser.hasInternalAccess,
      external: siteUser.hasExternalAccess,
      type: 'site-user'
    });

    return res.json({
      token,
      user: {
        id: siteUser.id,
        username: siteUser.username,
        prenom: siteUser.firstName,
        nom: siteUser.lastName,
        roles: [siteUser.role],
        type: 'site-user'
      }
    });
  } catch (e) {
    console.error('POST /auth/login (site-user) error:', e);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Connexion membre (matricule/email + mot de passe interne)
app.post('/auth/member-login', async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { identifier, matricule, password } = req.body;
    const loginIdentifier = identifier || matricule;
    const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    if (!loginIdentifier || !password) {
      return res.status(400).json({ error: 'Identifiant et mot de passe requis' });
    }

    const member = await prisma.member.findFirst({
      where: { OR: [{ matricule: loginIdentifier }, { email: loginIdentifier }] }
    });

    const logData = {
      type: 'LOGIN_ATTEMPT',
      ipAddress: clientIP,
      userAgent,
      details: `Tentative de connexion avec identifiant: ${loginIdentifier}`,
      ...(member ? { memberId: member.id } : {})
    };

    if (!member) {
      await prisma.connectionLog.create({ data: { ...logData, success: false, details: `${logData.details} - Membre non trouvé` } });
      return res.status(401).json({ error: 'Identifiant invalide' });
    }

    if (!member.loginEnabled) {
      await prisma.connectionLog.create({ data: { ...logData, success: false, details: `${logData.details} - Accès MyRBE non activé` } });
      return res.status(401).json({ error: 'Accès MyRBE non activé. Contactez un administrateur.' });
    }

    if (member.lockedUntil && member.lockedUntil > new Date()) {
      await prisma.connectionLog.create({ data: { ...logData, success: false, details: `${logData.details} - Compte verrouillé` } });
      return res.status(423).json({ error: 'Compte temporairement verrouillé. Réessayez plus tard.' });
    }

    const passwordToCheck = member.temporaryPassword || member.internalPassword;
    if (!passwordToCheck) {
      await prisma.connectionLog.create({ data: { ...logData, success: false, details: `${logData.details} - Mot de passe non configuré` } });
      return res.status(401).json({ error: 'Mot de passe non configuré. Contactez un administrateur.' });
    }

    let passwordValid = false;
    if (member.temporaryPassword && password === member.temporaryPassword) passwordValid = true;
    else if (member.internalPassword) passwordValid = await bcrypt.compare(password, member.internalPassword);

    if (!passwordValid) {
      const attempts = (member.loginAttempts || 0) + 1;
      const lockedUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;

      await prisma.member.update({ where: { id: member.id }, data: { loginAttempts: attempts, lockedUntil } });
      await prisma.connectionLog.create({
        data: { ...logData, success: false, details: `${logData.details} - Mot de passe incorrect (tentative ${attempts}/5)` }
      });
      return res.status(401).json({ error: 'Mot de passe incorrect' });
    }

    await prisma.member.update({
      where: { id: member.id },
      data: { loginAttempts: 0, lockedUntil: null, lastLoginAt: new Date(), mustChangePassword: !!member.temporaryPassword }
    });

    await prisma.connectionLog.create({
      data: { ...logData, type: 'LOGIN_SUCCESS', success: true, details: `Connexion réussie pour ${member.firstName} ${member.lastName}` }
    });

    const token = issueToken({ userId: member.id, username: member.matricule, role: member.role, type: 'member' });

    res.json({
      token,
      user: {
        id: member.id,
        username: member.matricule,
        prenom: member.firstName,
        nom: member.lastName,
        email: member.email,
        role: member.role,
        matricule: member.matricule,
        mustChangePassword: member.mustChangePassword || !!member.temporaryPassword,
        roles: [member.role],
        type: 'member'
      }
    });
  } catch (error) {
    console.error('❌ Erreur connexion membre:', error);
    res.status(500).json({ error: 'Erreur de connexion' });
  }
});

// Changer le mot de passe membre
app.post(['/auth/change-password', '/api/auth/change-password'], requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Mot de passe actuel et nouveau requis' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Le nouveau mot de passe doit faire au moins 6 caractères' });

    if (req.user.type === 'member') {
      const member = await prisma.member.findUnique({ where: { id: req.user.userId } });
      if (!member) return res.status(404).json({ error: 'Membre non trouvé' });

      const passwordToCheck = member.temporaryPassword || member.internalPassword;
      if (!passwordToCheck || !(await verifyPassword(currentPassword, passwordToCheck))) {
        return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
      }

      const hashedNewPassword = await hashPassword(newPassword);
      await prisma.member.update({
        where: { id: member.id },
        data: { internalPassword: hashedNewPassword, temporaryPassword: null, mustChangePassword: false, passwordChangedAt: new Date() }
      });

      res.json({ message: 'Mot de passe changé avec succès' });
    } else {
      res.status(403).json({ error: 'Cette fonction est réservée aux membres' });
    }
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Erreur lors du changement de mot de passe' });
  }
});

// Profil courant
app.get(['/api/me', '/api/auth/me'], requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    if (req.user.type === 'member') {
      const member = await prisma.member.findUnique({ where: { id: req.user.userId } });
      if (!member) return res.status(404).json({ error: 'Membre introuvable' });
      res.json({
        id: member.id,
        username: member.matricule,
        prenom: member.firstName,
        nom: member.lastName,
        email: member.email,
        role: member.role,
        matricule: member.matricule,
        mustChangePassword: member.mustChangePassword,
        roles: [member.role]
      });
    } else {
      res.json({
        username: req.user.username,
        prenom: req.user.prenom || '',
        nom: req.user.nom || '',
        roles: req.user.roles || []
      });
    }
  } catch (e) {
    console.error('Erreur /api/me:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ---------------- Vehicles (private) ----------------
app.get('/vehicles', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const vehicles = await prisma.vehicle.findMany({ orderBy: { parc: 'asc' } });
    res.json(vehicles.map(transformVehicle));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch vehicles' });
  }
});

app.get('/vehicles/:parc', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const vehicle = await prisma.vehicle.findUnique({ where: { parc } });
    if (!vehicle) return res.status(404).json({ error: 'Vehicle not found' });
    res.json(transformVehicle(vehicle));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch vehicle' });
  }
});

app.post('/vehicles', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const {
      parc, etat = 'disponible', immat, energie, miseEnCirculation,
      modele = '', type = 'Bus', marque, subtitle, description, history,
      caracteristiques, gallery
    } = req.body || {};

    if (!parc) return res.status(400).json({ error: 'parc requis' });

    const data = {
      parc, etat, modele, type,
      immat: immat || null,
      energie: energie || null,
      marque: marque || null,
      subtitle: subtitle || null,
      description: description || null,
      history: history || null,
      caracteristiques: stringifyJsonField(caracteristiques),
      gallery: stringifyJsonField(gallery),
      miseEnCirculation: miseEnCirculation ? new Date(miseEnCirculation) : null
    };

    const created = await prisma.vehicle.create({ data });
    res.json(transformVehicle(created));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Create failed' });
  }
});

app.put('/vehicles/:parc', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const body = { ...req.body };

    const existing = await prisma.vehicle.findUnique({ where: { parc } });
    if (!existing) return res.status(404).json({ error: 'Vehicle not found' });

    let caract = {};
    if (existing.caracteristiques) {
      try { caract = JSON.parse(existing.caracteristiques) || {}; } catch {}
    }

    const caractKeys = [
      'fleetNumbers','constructeur','miseEnCirculationTexte',
      'longueur','placesAssises','placesDebout','ufr',
      'preservePar','normeEuro','moteur','boiteVitesses',
      'nombrePortes','livree','girouette','climatisation'
    ];

    const directMap = {
      modele: 'modele',
      marque: 'marque',
      subtitle: 'subtitle',
      immat: 'immat',
      etat: 'etat',
      type: 'type',
      energie: 'energie',
      description: 'description',
      history: 'history',
      histoire: 'history'
    };

    const dataUpdate = {};
    Object.entries(directMap).forEach(([frontKey, dbKey]) => {
      if (body[frontKey] !== undefined) dataUpdate[dbKey] = body[frontKey] || null;
    });

    if (body.miseEnCirculation !== undefined) {
      dataUpdate.miseEnCirculation = body.miseEnCirculation ? new Date(body.miseEnCirculation) : null;
    }

    caractKeys.forEach(k => {
      if (body[k] !== undefined) caract[k] = body[k] || null;
    });

    let wroteArrayCaracteristiques = false;
    if (Array.isArray(body.caracteristiques)) {
      const normalized = body.caracteristiques
        .filter(it => it && (it.label != null || it.value != null))
        .map(it => ({ label: String(it.label ?? '').trim(), value: String(it.value ?? '').trim() }));
      dataUpdate.caracteristiques = JSON.stringify(normalized);
      wroteArrayCaracteristiques = true;
    }

    if (body.backgroundImage !== undefined) dataUpdate.backgroundImage = body.backgroundImage || null;
    if (body.backgroundPosition !== undefined) dataUpdate.backgroundPosition = body.backgroundPosition || null;

    if (!wroteArrayCaracteristiques) {
      dataUpdate.caracteristiques = Object.keys(caract).length ? JSON.stringify(caract) : null;
    }

    const updated = await prisma.vehicle.update({ where: { parc }, data: dataUpdate });
    res.json(transformVehicle(updated));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Update failed' });
  }
});

app.delete('/vehicles/:parc', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    await prisma.vehicle.delete({ where: { parc } });
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ---------- Galerie upload ----------
app.post('/vehicles/:parc/gallery', requireAuth, uploadGallery.array('images', 10), async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const v = await prisma.vehicle.findUnique({ where: { parc } });
    if (!v) return res.status(404).json({ error: 'Vehicle not found' });

    const existingGallery = parseJsonField(v.gallery);
    const existing = Array.isArray(existingGallery) ? existingGallery : [];

    const files = req.files || [];
    if (files.length === 0) return res.status(400).json({ error: 'Aucun fichier reçu' });

    const added = files.map(file => {
      const base64 = file.buffer.toString('base64');
      const mimeType = file.mimetype || 'image/jpeg';
      return `data:${mimeType};base64,${base64}`;
    });

    const MAX_GALLERY_IMAGES = 12;
    const gallery = Array.from(new Set(existing.concat(added))).slice(0, MAX_GALLERY_IMAGES);

    const updated = await prisma.vehicle.update({
      where: { parc },
      data: { gallery: stringifyJsonField(gallery) }
    });

    res.json({ gallery: parseJsonField(updated.gallery) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Upload gallery failed' });
  }
});

app.delete('/vehicles/:parc/gallery', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const { image } = req.body || {};
    if (!image) return res.status(400).json({ error: 'image requis' });

    const v = await prisma.vehicle.findUnique({ where: { parc } });
    if (!v) return res.status(404).json({ error: 'Vehicle not found' });

    const existingGallery = parseJsonField(v.gallery);
    const existing = Array.isArray(existingGallery) ? existingGallery : [];
    const updatedGallery = existing.filter(g => g !== image);

    const updated = await prisma.vehicle.update({
      where: { parc },
      data: { gallery: stringifyJsonField(updatedGallery) }
    });

    res.json({ gallery: parseJsonField(updated.gallery) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Delete gallery image failed' });
  }
});

app.post('/vehicles/:parc/background', requireAuth, uploadGallery.single('image'), async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    if (!req.file) return res.status(400).json({ error: 'image requis' });

    const v = await prisma.vehicle.findUnique({ where: { parc } });
    if (!v) return res.status(404).json({ error: 'Vehicle not found' });

    const base64 = req.file.buffer.toString('base64');
    const mimeType = req.file.mimetype || 'image/jpeg';
    const dataUrl = `data:${mimeType};base64,${base64}`;

    const updated = await prisma.vehicle.update({
      where: { parc },
      data: { backgroundImage: dataUrl }
    });

    res.json({ backgroundImage: updated.backgroundImage });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Upload background failed' });
  }
});

// ---------- Public vehicles ----------
app.get('/public/vehicles', async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const vehicles = await prisma.vehicle.findMany({
      select: {
        parc: true, type: true, modele: true, marque: true, subtitle: true,
        immat: true, etat: true, miseEnCirculation: true, energie: true,
        description: true, history: true, caracteristiques: true, gallery: true,
        backgroundImage: true, backgroundPosition: true
      }
    });
    res.json(vehicles.map(transformVehicle));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch public vehicles' });
  }
});

app.get('/public/vehicles/:parc', async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const vehicle = await prisma.vehicle.findUnique({
      where: { parc },
      select: {
        parc: true, type: true, modele: true, marque: true, subtitle: true,
        immat: true, etat: true, miseEnCirculation: true, energie: true,
        description: true, history: true, caracteristiques: true, gallery: true,
        backgroundImage: true, backgroundPosition: true
      }
    });
    if (!vehicle) return res.status(404).json({ error: 'Vehicle not found' });
    res.json(transformVehicle(vehicle));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch public vehicle' });
  }
});

// ---------- QR Code ----------
app.get('/vehicles/:parc/qr', requireAuth, async (req, res) => {
  try {
    const { parc } = req.params;
    const url = `https://www.association-rbe.fr/vehicule/${parc}`;
    const qr = await QRCode.toDataURL(url);
    res.json({ qrCode: qr, url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// ---------- Usages ----------
app.get('/vehicles/:parc/usages', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const usages = await prisma.usage.findMany({ where: { parc }, orderBy: { startedAt: 'desc' } });
    res.json(usages);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch usages' });
  }
});

app.post('/vehicles/:parc/usages', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const { startedAt, endedAt, conducteur, participants, note, relatedTo } = req.body || {};
    if (!startedAt) return res.status(400).json({ error: 'startedAt requis' });

    const data = {
      parc,
      startedAt: new Date(startedAt),
      endedAt: endedAt ? new Date(endedAt) : null,
      conducteur: conducteur || null,
      participants: participants || null,
      note: note || null,
      relatedTo: relatedTo || null
    };

    const created = await prisma.usage.create({ data });
    res.json(created);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Usage creation failed' });
  }
});

app.put('/usages/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const { startedAt, endedAt, conducteur, participants, note, relatedTo } = req.body || {};
    const data = {};
    if (startedAt !== undefined) data.startedAt = startedAt ? new Date(startedAt) : null;
    if (endedAt !== undefined) data.endedAt = endedAt ? new Date(endedAt) : null;
    if (conducteur !== undefined) data.conducteur = conducteur || null;
    if (participants !== undefined) data.participants = participants || null;
    if (note !== undefined) data.note = note || null;
    if (relatedTo !== undefined) data.relatedTo = relatedTo || null;

    const updated = await prisma.usage.update({ where: { id: parseInt(id) }, data });
    res.json(updated);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Usage update failed' });
  }
});

app.delete('/usages/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    await prisma.usage.delete({ where: { id: parseInt(id) } });
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Usage deletion failed' });
  }
});

// ---------- Reports ----------
app.get('/vehicles/:parc/reports', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const reports = await prisma.report.findMany({ where: { parc }, orderBy: { createdAt: 'desc' } });
    res.json(reports);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

app.post('/vehicles/:parc/reports', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const { description, usageId, filesMeta } = req.body || {};
    const data = { parc, description: description || null, usageId: usageId || null, filesMeta: filesMeta || null };
    const created = await prisma.report.create({ data });
    res.json(created);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Report creation failed' });
  }
});

app.put('/reports/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const { description, usageId, filesMeta } = req.body || {};
    const data = {};
    if (description !== undefined) data.description = description || null;
    if (usageId !== undefined) data.usageId = usageId || null;
    if (filesMeta !== undefined) data.filesMeta = filesMeta || null;

    const updated = await prisma.report.update({ where: { id: parseInt(id) }, data });
    res.json(updated);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Report update failed' });
  }
});

app.delete('/reports/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    await prisma.report.delete({ where: { id: parseInt(id) } });
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Report deletion failed' });
  }
});

// ---------- Flashes (public) ----------
app.get('/flashes/all', async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const flashes = await prisma.flash.findMany({ where: { active: true }, orderBy: { createdAt: 'desc' } });
    res.json(flashes);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch flashes' });
  }
});

// ---------- Events ----------
app.get('/events', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const rows = await prisma.event.findMany({ orderBy: { date: 'asc' } });
    res.json(rows.map(transformEvent));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Events fetch failed' });
  }
});

app.get('/events/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const evt = await prisma.event.findUnique({ where: { id: req.params.id } });
    if (!evt) return res.status(404).json({ error: 'Event not found' });
    res.json(transformEvent(evt));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Event fetch failed' });
  }
});

app.post('/events', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const b = req.body || {};
    if (!b.id) return res.status(400).json({ error: 'id requis' });

    const created = await prisma.event.create({
      data: {
        id: b.id,
        title: b.title || '',
        date: b.date ? new Date(b.date) : new Date(),
        time: b.time || null,
        location: b.location || null,
        description: b.description || null,
        helloAssoUrl: b.helloAssoUrl || null,
        adultPrice: b.adultPrice ?? null,
        childPrice: b.childPrice ?? null,
        vehicleId: b.vehicleId || null,
        status: b.status || 'DRAFT',
        layout: b.layout || null,
        extras: b.extras ? JSON.stringify(b.extras) : null
      }
    });
    res.status(201).json(transformEvent(created));
  } catch (e) {
    console.error(e);
    if (e.code === 'P2002') return res.status(409).json({ error: 'Duplicate id' });
    res.status(500).json({ error: 'Event create failed' });
  }
});

app.put('/events/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const existing = await prisma.event.findUnique({ where: { id: req.params.id } });
    if (!existing) return res.status(404).json({ error: 'Event not found' });
    const b = req.body || {};

    const updated = await prisma.event.update({
      where: { id: req.params.id },
      data: {
        title: b.title ?? existing.title,
        date: b.date ? new Date(b.date) : existing.date,
        time: b.time ?? existing.time,
        location: b.location ?? existing.location,
        description: b.description ?? existing.description,
        helloAssoUrl: b.helloAssoUrl ?? existing.helloAssoUrl,
        adultPrice: b.adultPrice ?? existing.adultPrice,
        childPrice: b.childPrice ?? existing.childPrice,
        vehicleId: b.vehicleId ?? existing.vehicleId,
        status: b.status ?? existing.status,
        layout: b.layout ?? existing.layout,
        extras: b.extras ? JSON.stringify(b.extras) : existing.extras
      }
    });
    res.json(transformEvent(updated));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Event update failed' });
  }
});

app.delete('/events/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    await prisma.event.delete({ where: { id: req.params.id } });
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Event delete failed' });
  }
});

// Public events
app.get('/public/events', async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const rows = await prisma.event.findMany({ where: { status: 'PUBLISHED' }, orderBy: { date: 'asc' } });
    res.json(rows.map(transformEvent));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Public events fetch failed' });
  }
});

app.get('/public/events/:id', async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const evt = await prisma.event.findUnique({ where: { id: req.params.id } });
    if (!evt || evt.status !== 'PUBLISHED') return res.status(404).json({ error: 'Event not found' });
    res.json(transformEvent(evt));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Public event fetch failed' });
  }
});

app.get('/public/vehicles/:parc/events', async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { parc } = req.params;
    const vehicle = await prisma.vehicle.findUnique({ where: { parc }, select: { parc: true } });
    if (!vehicle) return res.status(404).json({ error: 'Vehicle not found' });

    const events = await prisma.event.findMany({
      where: { vehicleId: parc, status: 'PUBLISHED' },
      orderBy: { date: 'asc' }
    });
    res.json(events.map(transformEvent));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch vehicle events' });
  }
});

// ---------- Newsletter ----------
const transformSubscriber = (s) => ({
  id: s.id, email: s.email, status: s.status, createdAt: s.createdAt, updatedAt: s.updatedAt
});

app.get('/newsletter', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const rows = await prisma.newsletterSubscriber.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(rows.map(transformSubscriber));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Fetch failed' });
  }
});

app.post('/newsletter/subscribe', async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { email } = req.body || {};
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email invalide' });

    const existing = await prisma.newsletterSubscriber.findUnique({ where: { email: email.toLowerCase() } });
    if (existing) return res.json({ ok: true, subscriber: transformSubscriber(existing) });

    const created = await prisma.newsletterSubscriber.create({
      data: { email: email.toLowerCase(), status: 'CONFIRMED' }
    });
    res.json({ ok: true, subscriber: transformSubscriber(created) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Subscribe failed' });
  }
});

app.post('/newsletter', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { email, status } = req.body || {};
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email invalide' });
    const created = await prisma.newsletterSubscriber.create({
      data: { email: email.toLowerCase(), status: status || 'CONFIRMED' }
    });
    res.json(transformSubscriber(created));
  } catch (e) {
    if (e.code === 'P2002') return res.status(409).json({ error: 'Email déjà inscrit' });
    console.error(e);
    res.status(500).json({ error: 'Create failed' });
  }
});

app.delete('/newsletter/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    await prisma.newsletterSubscriber.delete({ where: { id: req.params.id } });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ---------- Stocks ----------
app.get('/api/stocks', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { search, category, status, lowStock } = req.query;

    const where = {};
    if (category && category !== 'ALL') where.category = String(category);
    if (status && status !== 'ALL') where.status = String(status);
    if (search) {
      const s = String(search).trim();
      where.OR = [
        { name: { contains: s, mode: 'insensitive' } },
        { reference: { contains: s, mode: 'insensitive' } },
        { description: { contains: s, mode: 'insensitive' } }
      ];
    }

    const rows = await prisma.stock.findMany({ where, orderBy: { name: 'asc' } });
    const filtered = (String(lowStock) === 'true')
      ? rows.filter(r => (r.quantity ?? 0) <= (r.minQuantity ?? 0))
      : rows;

    res.json({ stocks: filtered.map(transformStock) });
  } catch (e) {
    console.error('stocks list error:', e);
    res.json({ stocks: [] });
  }
});

app.get('/api/stocks/stats', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const [totalItems, agg] = await Promise.all([
      prisma.stock.count(),
      prisma.stock.aggregate({ _sum: { quantity: true } })
    ]);

    const all = await prisma.stock.findMany({ select: { quantity: true, minQuantity: true } });
    let lowStockCount = 0;
    let outOfStockCount = 0;
    for (const s of all) {
      if ((s.quantity ?? 0) <= (s.minQuantity ?? 0)) lowStockCount++;
      if ((s.quantity ?? 0) === 0) outOfStockCount++;
    }

    res.json({
      totalItems,
      totalQuantity: agg?._sum?.quantity || 0,
      lowStockCount,
      outOfStockCount
    });
  } catch (e) {
    console.error('stocks/stats error:', e);
    res.json({ totalItems: 0, totalQuantity: 0, lowStockCount: 0, outOfStockCount: 0 });
  }
});

// ---------- Finance - opérations programmées ----------
app.get(['/finance/scheduled-operations', '/api/finance/scheduled-operations'], requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const operations = await prisma.scheduledOperation.findMany({ orderBy: { dueDate: 'asc' } });
    res.json({ operations });
  } catch (error) {
    console.error('Erreur récupération opérations programmées:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post(['/finance/scheduled-operations', '/api/finance/scheduled-operations'], requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { type, description, amount, dueDate, category, recurring, notes } = req.body;
    const operation = await prisma.scheduledOperation.create({
      data: {
        type,
        description,
        amount: parseFloat(amount),
        dueDate: dueDate ? new Date(dueDate) : null,
        category,
        recurring: recurring || 'none',
        notes,
        createdBy: req.user?.email || 'system'
      }
    });
    res.json(operation);
  } catch (error) {
    console.error('Erreur création opération programmée:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ---------- RetroReports (API unique, sans doublons) ----------
app.get('/admin/retro-reports', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const reports = await prisma.retroReport.findMany({
      include: { comments: { orderBy: { createdAt: 'desc' } } },
      orderBy: { createdAt: 'desc' }
    });
    res.json({ reports });
  } catch (error) {
    console.error('Erreur récupération RétroReports:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/admin/retro-reports', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;

  try {
    const { title, description, category, priority, type } = req.body;
    if (!title || !description) {
      return res.status(400).json({ error: 'Titre et description requis' });
    }

    const report = await prisma.retroReport.create({
      data: {
        title: String(title).trim(),
        description: String(description).trim(),
        category: category ? String(category).trim() : null,
        priority: priority || 'medium',
        type: type || 'bug',
        status: 'open',
        createdBy: req.user?.email || req.user?.matricule || 'system'
      },
      include: { comments: { orderBy: { createdAt: 'desc' } } }
    });

    res.status(201).json(report);
  } catch (error) {
    console.error('Erreur création RétroReport:', error);
    if (error.code === 'P2002') return res.status(400).json({ error: 'Contrainte d\'unicité violée', details: error.meta });
    if (error.code && error.code.startsWith('P')) return res.status(500).json({ error: 'Erreur base de données', code: error.code, details: error.meta });
    res.status(500).json({ error: 'Erreur serveur lors de la création', message: error.message });
  }
});

app.post('/admin/retro-reports/:id/comments', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const { message, status } = req.body;
    if (!message) return res.status(400).json({ error: 'Message requis' });

    const comment = await prisma.retroReportComment.create({
      data: {
        retroReportId: id, // FK
        message,
        author: req.user?.email || req.user?.matricule || 'system'
      }
    });

    if (status) {
      await prisma.retroReport.update({ where: { id }, data: { status } });
    }

    res.json(comment);
  } catch (error) {
    console.error('Erreur ajout commentaire RétroReport:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ---------- Endpoints API Retro-Reports publics (si besoin UI) ----------
app.get('/api/retro-reports', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const reports = await prisma.retroReport.findMany({
      include: {
        comments: {
          orderBy: { createdAt: 'desc' }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
    res.json(reports);
  } catch (error) {
    console.error('Erreur récupération retro reports:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/retro-reports', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { title, description, priority, category, impact, steps } = req.body;
    const report = await prisma.retroReport.create({
      data: {
        title,
        description,
        priority: priority || 'MEDIUM',
        category: category || 'BUG',
        impact: impact || 'MINOR',
        steps: steps || '',
        status: 'OPEN',
        reporterEmail: req.userEmail || null,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });
    res.status(201).json(report);
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.post('/api/retro-reports/:id/comments', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const { message } = req.body;
    const comment = await prisma.retroReportComment.create({
      data: {
        reportId: parseInt(id, 10),
        message,
        author: req.userEmail || 'system'
      }
    });
    res.status(201).json(comment);
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

// ---------- Finance simulations ----------
function getFrequencyMultiplier(frequency) {
  const multipliers = {
    DAILY: 30,
    WEEKLY: 4.33,
    MONTHLY: 1,
    QUARTERLY: 0.33,
    YEARLY: 0.083
  };
  return multipliers[frequency] || 1;
}

app.get('/api/finance/simulations', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const scenarios = await prisma.financeSimulationScenario.findMany({
      include: { incomeItems: true, expenseItems: true },
      orderBy: { createdAt: 'desc' }
    });
    res.json({
      scenarios: scenarios.map(s => ({
        ...s,
        totalMonthlyIncome: s.incomeItems.reduce((sum, i) => sum + i.amount, 0),
        totalMonthlyExpenses: s.expenseItems.reduce((sum, e) => sum + e.amount, 0),
        itemsCount: s.incomeItems.length + s.expenseItems.length
      }))
    });
  } catch (error) {
    console.error('❌ Erreur récupération scénarios:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.post('/api/finance/simulations', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { name, description, projectionMonths } = req.body;
    if (!name || !description) return res.status(400).json({ error: 'Nom et description sont obligatoires' });

    const scenario = await prisma.financeSimulationScenario.create({
      data: {
        name: name.trim(),
        description: description.trim(),
        projectionMonths: projectionMonths || 12,
        createdBy: req.user.matricule || req.user.email || 'system',
        status: 'DRAFT'
      }
    });

    res.status(201).json({
      scenario: { ...scenario, totalMonthlyIncome: 0, totalMonthlyExpenses: 0, itemsCount: 0 },
      message: 'Scénario créé avec succès'
    });
  } catch (error) {
    console.error('❌ Erreur création scénario:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.get('/api/finance/simulations/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const scenario = await prisma.financeSimulationScenario.findUnique({
      where: { id },
      include: {
        incomeItems: { orderBy: { createdAt: 'asc' } },
        expenseItems: { orderBy: { createdAt: 'asc' } }
      }
    });
    if (!scenario) return res.status(404).json({ error: 'Scénario non trouvé' });

    const totalMonthlyIncome = scenario.incomeItems.reduce((sum, i) => sum + i.amount, 0);
    const totalMonthlyExpenses = scenario.expenseItems.reduce((sum, e) => sum + e.amount, 0);

    res.json({
      scenario: {
        ...scenario,
        totalMonthlyIncome,
        totalMonthlyExpenses,
        monthlyNet: totalMonthlyIncome - totalMonthlyExpenses,
        itemsCount: scenario.incomeItems.length + scenario.expenseItems.length
      }
    });
  } catch (error) {
    console.error('❌ Erreur récupération scénario:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.put('/api/finance/simulations/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const { name, description, projectionMonths, status } = req.body;
    const scenario = await prisma.financeSimulationScenario.update({
      where: { id },
      data: {
        name: name?.trim(),
        description: description?.trim(),
        projectionMonths,
        status,
        updatedAt: new Date()
      }
    });
    res.json({ scenario, message: 'Scénario mis à jour avec succès' });
  } catch (error) {
    console.error('❌ Erreur mise à jour scénario:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.post('/api/finance/simulations/:id/income', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const { description, amount, category, frequency } = req.body;
    if (!description || !amount || amount <= 0) return res.status(400).json({ error: 'Description et montant positif requis' });

    const incomeItem = await prisma.financeSimulationIncomeItem.create({
      data: {
        scenarioId: id,
        description: description.trim(),
        amount: parseFloat(amount),
        category: category || 'AUTRE',
        frequency: frequency || 'MONTHLY'
      }
    });
    res.status(201).json({ incomeItem, message: 'Recette ajoutée avec succès' });
  } catch (error) {
    console.error('❌ Erreur ajout recette:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.post('/api/finance/simulations/:id/expense', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const { description, amount, category, frequency } = req.body;
    if (!description || !amount || amount <= 0) return res.status(400).json({ error: 'Description et montant positif requis' });

    const expenseItem = await prisma.financeSimulationExpenseItem.create({
      data: {
        scenarioId: id,
        description: description.trim(),
        amount: parseFloat(amount),
        category: category || 'AUTRE',
        frequency: frequency || 'MONTHLY'
      }
    });
    res.status(201).json({ expenseItem, message: 'Dépense ajoutée avec succès' });
  } catch (error) {
    console.error('❌ Erreur ajout dépense:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.delete('/api/finance/simulations/income/:itemId', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { itemId } = req.params;
    await prisma.financeSimulationIncomeItem.delete({ where: { id: itemId } });
    res.json({ message: 'Recette supprimée avec succès' });
  } catch (error) {
    console.error('❌ Erreur suppression recette:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.delete('/api/finance/simulations/expense/:itemId', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { itemId } = req.params;
    await prisma.financeSimulationExpenseItem.delete({ where: { id: itemId } });
    res.json({ message: 'Dépense supprimée avec succès' });
  } catch (error) {
    console.error('❌ Erreur suppression dépense:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.post('/api/finance/simulations/:id/run', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const scenario = await prisma.financeSimulationScenario.findUnique({
      where: { id },
      include: { incomeItems: true, expenseItems: true }
    });
    if (!scenario) return res.status(404).json({ error: 'Scénario non trouvé' });

    const monthlyIncome = scenario.incomeItems.reduce((sum, item) => sum + (item.amount * getFrequencyMultiplier(item.frequency)), 0);
    const monthlyExpenses = scenario.expenseItems.reduce((sum, item) => sum + (item.amount * getFrequencyMultiplier(item.frequency)), 0);

    const latestBalance = await prisma.financeBalance.findFirst({ orderBy: { createdAt: 'desc' } });
    const currentBalance = latestBalance?.balance || 0;

    const projection = [];
    let runningBalance = currentBalance;
    for (let month = 1; month <= scenario.projectionMonths; month++) {
      const monthlyNet = monthlyIncome - monthlyExpenses;
      runningBalance += monthlyNet;
      projection.push({
        month,
        startBalance: month === 1 ? currentBalance : projection[month - 2].endBalance,
        income: monthlyIncome,
        expenses: monthlyExpenses,
        net: monthlyIncome - monthlyExpenses,
        endBalance: runningBalance
      });
    }

    const finalBalance = projection.at(-1).endBalance;
    const totalChange = finalBalance - currentBalance;

    res.json({
      simulation: {
        scenarioId: id,
        scenarioName: scenario.name,
        startingBalance: currentBalance,
        finalBalance,
        totalChange,
        monthlyIncome,
        monthlyExpenses,
        monthlyNet: monthlyIncome - monthlyExpenses,
        projectionMonths: scenario.projectionMonths,
        projection,
        runDate: new Date(),
        summary: {
          isPositive: totalChange >= 0,
          breakEvenMonth: (projection.findIndex(p => p.endBalance < 0) + 1) || null,
          averageBalance: projection.reduce((sum, p) => sum + p.endBalance, 0) / projection.length
        }
      }
    });
  } catch (error) {
    console.error('❌ Erreur exécution simulation:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

// ---------- Members (GET, stats, GET by id, PUT) ----------
app.get('/api/members', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const members = await prisma.user.findMany({
      select: {
        id: true, matricule: true, nom: true, prenom: true, email: true,
        telephone: true, ville: true, statut: true, isActive: true,
        isValidated: true, role: true, createdAt: true, updatedAt: true
      },
      orderBy: [{ nom: 'asc' }, { prenom: 'asc' }]
    });

    res.json({
      members,
      total: members.length,
      active: members.filter(m => m.isActive).length,
      validated: members.filter(m => m.isValidated).length,
      pending: members.filter(m => !m.isValidated).length
    });
  } catch (error) {
    console.error('❌ Erreur récupération membres:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.get('/api/members/stats', requireAuth, async (_req, res) => {
  if (!ensureDB(res)) return;
  try {
    const stats = await prisma.user.groupBy({ by: ['statut', 'isActive', 'isValidated'], _count: true });
    const totalMembers = await prisma.user.count();
    const activeMembers = await prisma.user.count({ where: { isActive: true } });
    const validatedMembers = await prisma.user.count({ where: { isValidated: true } });
    const pendingMembers = await prisma.user.count({ where: { isValidated: false } });

    const thisMonth = new Date();
    const monthStart = new Date(thisMonth.getFullYear(), thisMonth.getMonth(), 1);
    const newThisMonth = await prisma.user.count({ where: { createdAt: { gte: monthStart } } });

    res.json({
      total: totalMembers,
      active: activeMembers,
      validated: validatedMembers,
      pending: pendingMembers,
      newThisMonth,
      breakdown: stats
    });
  } catch (error) {
    console.error('❌ Erreur stats membres:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.get('/api/members/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const member = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true, matricule: true, nom: true, prenom: true, email: true,
        telephone: true, ville: true, statut: true, isActive: true,
        isValidated: true, role: true, createdAt: true, updatedAt: true
      }
    });
    if (!member) return res.status(404).json({ error: 'Membre non trouvé' });
    res.json({ member });
  } catch (error) {
    console.error('❌ Erreur récupération membre:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

app.put('/api/members/:id', requireAuth, async (req, res) => {
  if (!ensureDB(res)) return;
  try {
    const { id } = req.params;
    const currentUser = req.userId ? await prisma.user.findUnique({ where: { id: req.userId } }) : null;
    if (!currentUser) return res.status(401).json({ error: 'Utilisateur courant introuvable' });

    if (currentUser.role !== 'ADMIN' && currentUser.id !== id) {
      return res.status(403).json({ error: 'Accès refusé', message: 'Seuls les administrateurs peuvent modifier les membres' });
    }

    const allowed = [
      'matricule','nom','prenom','email','telephone','ville',
      'statut','isActive','isValidated','role'
    ];
    const data = {};
    for (const k of allowed) {
      if (k in req.body) data[k] = req.body[k];
    }
    data.updatedAt = new Date();

    const updatedMember = await prisma.user.update({ where: { id }, data });
    res.json({ member: updatedMember });
  } catch (error) {
    console.error('❌ Erreur mise à jour membre:', error);
    res.status(500).json({ error: 'Erreur serveur', message: error.message });
  }
});

// ---------------- Start server ----------------
app.listen(PORT, () => {
  console.log(`🚀 Serveur prêt sur http://localhost:${PORT}`);
});
