import crypto from 'crypto';
import { validateToken } from './_tokens.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    console.log('🎯 Generate API called');
    
    // 🔐 VERIFICAR TOKEN DE ACESSO
    const accessToken = req.query.token;
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    console.log('📧 Token received:', accessToken ? accessToken.substring(0, 12) + '...' : 'NONE');

    // ❌ BLOQUEAR: Sem token
    if (!accessToken) {
      console.log('🚫 BLOCKED: No access token provided');
      return res.status(403).send('ACCESS DENIED: Complete LootLabs tasks first');
    }

    // ❌ BLOQUEAR: Token inválido
    const tokenValidation = validateToken(accessToken);
    if (!tokenValidation.valid) {
      console.log('🚫 BLOCKED: Invalid token -', tokenValidation.reason);
      return res.status(403).send('ACCESS DENIED: Invalid or expired token');
    }

    // ✅ TOKEN VÁLIDO - Gerar key
    console.log('✅ Token validated, generating key...');
    
    const key = crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    
    console.log('🔑 Key generated:', key);

    // Webhook do Discord
    fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: "🔑 New 24h Key Generated",
          description: `**Key:** ||${key}||\n**Token:** ${accessToken.substring(0, 12)}...\n**IP:** ${clientIP}\n**Time:** ${new Date().toLocaleString()}`,
          color: 16711680,
          timestamp: new Date().toISOString(),
          footer: { text: "Key System • Token Protected" }
        }]
      })
    }).catch(error => {
      console.log('⚠️ Discord webhook failed:', error.message);
    });

    res.setHeader('Content-Type', 'text/plain');
    res.send(key);

  } catch (error) {
    console.error('❌ Generate API error:', error);
    res.status(500).send('ERROR: Failed to generate key');
  }
}