import crypto from 'crypto';

// No Node.js 18+, fetch está disponível nativamente, então não precisamos do node-fetch

export default async function handler(req, res) {
  // Configurar CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Permitir apenas métodos GET
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    console.log('🔑 Starting key generation...');
    
    // Gerar key no formato XXXX-XXXX-XXXX
    const keyBuffer = crypto.randomBytes(12);
    const keyHex = keyBuffer.toString('hex').toUpperCase();
    const key = keyHex.match(/.{4}/g).join('-');
    
    console.log('✅ Key generated:', key);

    // Webhook do Discord - Vamos tentar, mas se falhar, não quebra a função
    const webhookURL = "https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH";
    
    console.log('📤 Attempting Discord webhook...');
    
    // Usando fetch nativo (disponível no Node.js 18+)
    fetch(webhookURL, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        embeds: [{
          title: "🔑 New 24h Key Generated",
          description: `**Key:** ||${key}||\n**Time:** ${new Date().toLocaleString()}`,
          color: 16711680,
          timestamp: new Date().toISOString(),
          footer: { 
            text: "Key System • 24h Temporary" 
          }
        }]
      })
    })
    .then(response => {
      if (response.ok) {
        console.log('✅ Discord webhook sent successfully');
      } else {
        console.warn('⚠️ Discord webhook response not OK:', response.status);
      }
    })
    .catch(error => {
      console.warn('⚠️ Discord webhook failed, but continuing:', error.message);
    });

    // SEMPRE retorna a key, mesmo se o webhook falhar
    console.log('🎯 Returning key to client:', key);
    res.status(200).setHeader('Content-Type', 'text/plain; charset=utf-8').send(key);
    
  } catch (error) {
    console.error('❌ Error in generate API:', error);
    res.status(500).setHeader('Content-Type', 'text/plain; charset=utf-8').send('Error generating key');
  }
}