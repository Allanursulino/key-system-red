import crypto from 'crypto';
import { validateApprovalCode } from './approve.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const approvalCode = req.query.code;
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    console.log('🔍 Key generation attempt - Code:', approvalCode, 'IP:', clientIP);

    // ❌ BLOQUEAR: Sem código de aprovação
    if (!approvalCode) {
      console.log('🚫 BLOCKED: No approval code');
      return res.status(403).send('ACCESS DENIED: Please complete LootLabs verification first. Visit the homepage and start verification.');
    }

    // ✅ VERIFICAR CÓDIGO DE APROVAÇÃO
    const codeValidation = validateApprovalCode(approvalCode);
    if (!codeValidation.valid) {
      console.log('🚫 BLOCKED: Invalid approval code -', codeValidation.reason);
      return res.status(403).send('ACCESS DENIED: Invalid or expired verification code. Please restart verification.');
    }

    // ✅ GERAR KEY
    console.log('✅ Approval code valid, generating key...');
    
    const key = crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    
    console.log('🔑 Key generated:', key);

    // 📨 DISCORD WEBHOOK
    fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: "✅ Key Generated (Code Verified)",
          description: `**Key:** ||${key}||\n**Code:** ${approvalCode}\n**IP:** ${clientIP}\n**Time:** ${new Date().toLocaleString()}`,
          color: 65280,
          timestamp: new Date().toISOString(),
          footer: { text: "Key System • Code Verification" }
        }]
      })
    }).catch(console.error);

    res.setHeader('Content-Type', 'text/plain');
    res.send(key);

  } catch (error) {
    console.error('❌ Generate API error:', error);
    res.status(500).send('ERROR: Failed to generate key');
  }
}