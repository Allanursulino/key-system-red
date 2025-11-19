import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  // Configurar CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // Gerar key no formato XXXX-XXXX-XXXX
    const key = crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    
    console.log('Key generated:', key);

    // Enviar para webhook do Discord
    const webhookURL = "https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH";
    
    await fetch(webhookURL, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "User-Agent": "KeySystem/1.0"
      },
      body: JSON.stringify({
        embeds: [{
          title: "🔑 New 24h Key Generated",
          description: `**Key:** ||${key}||\n**Time:** ${new Date().toLocaleString()}`,
          color: 16711680,
          timestamp: new Date().toISOString(),
          footer: { text: "Key System • 24h Temporary" }
        }]
      })
    }).then(response => {
      if (!response.ok) {
        console.error('Discord webhook error:', response.status);
      }
    }).catch(error => {
      console.error('Webhook fetch error:', error);
    });

    // Retornar a key
    res.status(200).setHeader('Content-Type', 'text/plain; charset=utf-8').send(key);
    
  } catch (error) {
    console.error('Error in generate API:', error);
    res.status(500).send('Error generating key');
  }
}