import nodemailer from 'nodemailer';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Configuration du transporteur email
const createTransporter = () => {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
};

// Template HTML de base pour la newsletter
const createEmailTemplate = (content, unsubscribeUrl = '') => {
  return `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Newsletter RétroBus Essonne</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            background-color: #f4f4f4;
        }
        .container {
            background-color: #ffffff;
            margin: 20px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #be003c, #dc143c);
            color: white;
            padding: 30px 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: bold;
        }
        .header p {
            margin: 5px 0 0 0;
            opacity: 0.9;
            font-size: 14px;
        }
        .content {
            padding: 30px 20px;
        }
        .content h2 {
            color: #be003c;
            border-bottom: 2px solid #be003c;
            padding-bottom: 5px;
        }
        .content p {
            margin-bottom: 15px;
        }
        .button {
            display: inline-block;
            background-color: #be003c;
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            margin: 10px 0;
        }
        .button:hover {
            background-color: #dc143c;
        }
        .footer {
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #666;
            border-top: 1px solid #eee;
        }
        .footer a {
            color: #be003c;
            text-decoration: none;
        }
        .social-links {
            margin: 15px 0;
        }
        .social-links a {
            margin: 0 10px;
            color: #be003c;
            text-decoration: none;
        }
        @media (max-width: 600px) {
            .container {
                margin: 10px;
            }
            .header, .content, .footer {
                padding: 20px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚌 RétroBus Essonne</h1>
            <p>Newsletter • Association de préservation du patrimoine roulant</p>
        </div>
        
        <div class="content">
            ${content}
        </div>
        
        <div class="footer">
            <div class="social-links">
                <a href="https://www.facebook.com/RetrobusEssonne">Facebook</a> •
                <a href="https://retrobus-essonne.fr">Site Web</a> •
                <a href="mailto:association.rbe@gmail.com">Contact</a>
            </div>
            <p>
                <strong>Association RétroBus Essonne</strong><br>
                Préservation et mise en valeur du patrimoine roulant francilien
            </p>
            ${unsubscribeUrl ? `
            <p>
                <a href="${unsubscribeUrl}" style="color: #999; font-size: 11px;">
                    Se désabonner de cette newsletter
                </a>
            </p>
            ` : ''}
            <p style="margin-top: 15px; font-size: 10px; color: #999;">
                Cet email a été envoyé automatiquement. Merci de ne pas répondre directement.
            </p>
        </div>
    </div>
</body>
</html>
  `;
};

// Service principal de gestion des campagnes
export const newsletterService = {
  // Créer une nouvelle campagne
  createCampaign: async (data) => {
    const campaign = await prisma.newsletterCampaign.create({
      data: {
        title: data.title,
        subject: data.subject,
        content: data.content,
        status: 'DRAFT',
        createdBy: data.createdBy || 'system',
        scheduledAt: data.scheduledAt ? new Date(data.scheduledAt) : null
      }
    });
    return campaign;
  },

  // Récupérer toutes les campagnes
  getCampaigns: async (filters = {}) => {
    const where = {};
    if (filters.status) where.status = filters.status;
    
    return await prisma.newsletterCampaign.findMany({
      where,
      include: {
        _count: {
          select: { sends: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
  },

  // Récupérer une campagne par ID
  getCampaignById: async (id) => {
    return await prisma.newsletterCampaign.findUnique({
      where: { id },
      include: {
        sends: {
          include: {
            subscriber: true
          }
        }
      }
    });
  },

  // Prévisualiser une campagne
  previewCampaign: async (campaignId) => {
    const campaign = await prisma.newsletterCampaign.findUnique({
      where: { id: campaignId }
    });
    
    if (!campaign) throw new Error('Campagne non trouvée');
    
    const unsubscribeUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/unsubscribe?token=PREVIEW_TOKEN`;
    const htmlContent = createEmailTemplate(campaign.content, unsubscribeUrl);
    
    return {
      subject: campaign.subject,
      html: htmlContent,
      text: campaign.content.replace(/<[^>]*>/g, '') // Strip HTML for text version
    };
  },

  // Préparer l'envoi d'une campagne
  prepareCampaignSend: async (campaignId) => {
    const campaign = await prisma.newsletterCampaign.findUnique({
      where: { id: campaignId }
    });
    
    if (!campaign) throw new Error('Campagne non trouvée');
    if (campaign.status !== 'DRAFT') throw new Error('Seules les campagnes en brouillon peuvent être envoyées');

    // Récupérer tous les abonnés confirmés
    const subscribers = await prisma.newsletterSubscriber.findMany({
      where: { status: 'CONFIRMED' }
    });

    // Créer les entrées d'envoi
    const sends = await Promise.all(
      subscribers.map(subscriber => 
        prisma.newsletterCampaignSend.upsert({
          where: {
            campaignId_subscriberId: {
              campaignId: campaignId,
              subscriberId: subscriber.id
            }
          },
          update: {},
          create: {
            campaignId: campaignId,
            subscriberId: subscriber.id,
            email: subscriber.email,
            status: 'PENDING'
          }
        })
      )
    );

    // Marquer la campagne comme prête à envoyer
    await prisma.newsletterCampaign.update({
      where: { id: campaignId },
      data: { 
        status: 'SENDING',
        totalSent: 0
      }
    });

    return { preparedSends: sends.length };
  },

  // Envoyer une campagne
  sendCampaign: async (campaignId) => {
    const campaign = await prisma.newsletterCampaign.findUnique({
      where: { id: campaignId },
      include: {
        sends: {
          where: { status: 'PENDING' },
          include: { subscriber: true }
        }
      }
    });

    if (!campaign) throw new Error('Campagne non trouvée');
    if (campaign.status !== 'SENDING') throw new Error('La campagne doit être en cours d\'envoi');

    const transporter = createTransporter();
    let successCount = 0;
    let errorCount = 0;

    console.log(`📧 Début d'envoi de la campagne "${campaign.title}" à ${campaign.sends.length} abonnés`);

    // Envoyer à chaque abonné
    for (const send of campaign.sends) {
      try {
        const unsubscribeUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/unsubscribe?token=${send.id}`;
        const htmlContent = createEmailTemplate(campaign.content, unsubscribeUrl);
        
        const mailOptions = {
          from: `"RétroBus Essonne" <${process.env.SMTP_USER}>`,
          to: send.email,
          subject: campaign.subject,
          html: htmlContent,
          text: campaign.content.replace(/<[^>]*>/g, ''),
          headers: {
            'List-Unsubscribe': `<${unsubscribeUrl}>`,
            'X-Campaign-ID': campaignId,
            'X-Send-ID': send.id
          }
        };

        await transporter.sendMail(mailOptions);
        
        // Marquer comme envoyé
        await prisma.newsletterCampaignSend.update({
          where: { id: send.id },
          data: { 
            status: 'SENT',
            sentAt: new Date()
          }
        });

        successCount++;
        console.log(`✅ Email envoyé à ${send.email}`);

        // Petit délai pour éviter de surcharger le serveur SMTP
        await new Promise(resolve => setTimeout(resolve, 100));

      } catch (error) {
        console.error(`❌ Erreur envoi à ${send.email}:`, error.message);
        
        // Marquer comme échoué
        await prisma.newsletterCampaignSend.update({
          where: { id: send.id },
          data: { 
            status: 'FAILED',
            errorMessage: error.message
          }
        });

        errorCount++;
      }
    }

    // Mettre à jour les statistiques de la campagne
    await prisma.newsletterCampaign.update({
      where: { id: campaignId },
      data: { 
        status: 'SENT',
        sentAt: new Date(),
        totalSent: successCount
      }
    });

    console.log(`📊 Campagne terminée: ${successCount} envoyés, ${errorCount} erreurs`);

    return {
      success: successCount,
      errors: errorCount,
      total: campaign.sends.length
    };
  },

  // Envoyer un email de test
  sendTestEmail: async (campaignId, testEmail) => {
    const campaign = await prisma.newsletterCampaign.findUnique({
      where: { id: campaignId }
    });

    if (!campaign) throw new Error('Campagne non trouvée');

    const transporter = createTransporter();
    const htmlContent = createEmailTemplate(campaign.content, '#');
    
    const mailOptions = {
      from: `"RétroBus Essonne (TEST)" <${process.env.SMTP_USER}>`,
      to: testEmail,
      subject: `[TEST] ${campaign.subject}`,
      html: htmlContent,
      text: campaign.content.replace(/<[^>]*>/g, ''),
      headers: {
        'X-Campaign-ID': campaignId,
        'X-Test-Email': 'true'
      }
    };

    await transporter.sendMail(mailOptions);
    return { success: true };
  },

  // Supprimer une campagne
  deleteCampaign: async (campaignId) => {
    return await prisma.newsletterCampaign.delete({
      where: { id: campaignId }
    });
  },

  // Récupérer les statistiques d'une campagne
  getCampaignStats: async (campaignId) => {
    const sends = await prisma.newsletterCampaignSend.groupBy({
      by: ['status'],
      where: { campaignId },
      _count: true
    });

    const stats = {
      pending: 0,
      sent: 0,
      failed: 0,
      opened: 0,
      clicked: 0
    };

    sends.forEach(send => {
      stats[send.status.toLowerCase()] = send._count;
    });

    return stats;
  }
};