FROM node:20-alpine

WORKDIR /app

# Fix OpenSSL AVANT tout (important pour Prisma)
RUN apk add --no-cache openssl

# Copier les fichiers nécessaires pour la génération
COPY package*.json ./
COPY prisma ./prisma

# Installer les dépendances (avec dev deps pour générer Prisma)
RUN npm ci || npm install

# Générer Prisma client AVEC les nouveaux binary targets
RUN npx prisma generate

# Copier le reste du code
COPY . .

# Optimiser: retirer dev deps après génération
RUN npm prune --production

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "src/server.js"]