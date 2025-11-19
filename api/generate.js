import crypto from 'crypto';

// Armazenar IPs que completaram LootLabs (em produção use Redis)
const approvedIPs = new Map();
// Armazenar keys já geradas (evitar duplicatas)
const generatedKeys = new Map();

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || '';
    const referer = req.headers['referer'] || '';
    
    console.log('🔍 Access attempt from IP:', clientIP);
    console.log('📱 User Agent:', userAgent);
    console.log('🔗 Referer:', referer);

    // ✅ PERMITIR: Se veio do LootLabs (verificação por Referer)
    const isFromLootLabs = referer.includes('lootlabs.gg') || 
                           userAgent.includes('lootlabs') ||
                           req.headers['x-verified'] === 'lootlabs';

    // ✅ PERMITIR: Se IP já foi aprovado recentemente
    const isApprovedIP = approvedIPs.has(clientIP);
    
    if (isFromLootLabs) {
      console.log('✅ Approved: Came from LootLabs');
      // Marcar IP como aprovado por 10 minutos
      approvedIPs.set(clientIP, {
        approvedAt: Date.now(),
        expires: Date.now() + (10 * 60 * 1000),
        source: 'lootlabs-referer'
      });
    } 
    else if (isApprovedIP) {
      const ipData = approvedIPs.get(clientIP);
      if (Date.now() > ipData.expires) {
        approvedIPs.delete(clientIP);
        console.log('❌ IP approval expired');
        return res.status(403).send('ACCESS DENIED: Please complete LootLabs tasks again');
      }
      console.log('✅ Approved: Previously approved IP');
    }
    else {
      // ❌ BLOQUEAR: Acesso direto sem passar pelo LootLabs
      console.log('🚫 BLOCKED: Direct access detected');
      console.log('📊 Approved IPs:', Array.from(approvedIPs.keys()));
      return res.status(403).send('ACCESS DENIED: Please complete LootLabs tasks first. Go to homepage and click the button.');
    }

    // ✅ GERAR KEY
    console.log('🔑 Generating key for approved access...');
    
    const key = crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    
    console.log('✅ Key generated:', key);

    // Webhook do Discord
    fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: "🔑 New 24h Key Generated",
          description: `**Key:** ||${key}||\n**IP:** ${clientIP}\n**Source:** ${isFromLootLabs ? 'LootLabs' : 'Approved IP'}\n**Time:** ${new Date().toLocaleString()}`,
          color: 16711680,
          timestamp: new Date().toISOString(),
          footer: { text: "Key System • IP Protected" }
        }]
      })
    }).catch(error => {
      console.log('⚠️ Discord webhook failed:', error.message);
    });

    // Limpar IPs expirados
    cleanupApprovedIPs();

    res.setHeader('Content-Type', 'text/plain');
    res.send(key);

  } catch (error) {
    console.error('❌ Generate API error:', error);
    res.status(500).send('ERROR: Failed to generate key');
  }
}

// Limpar IPs aprovados expirados
function cleanupApprovedIPs() {
  const now = Date.now();
  for (const [ip, data] of approvedIPs.entries()) {
    if (now > data.expires) {
      approvedIPs.delete(ip);
    }
  }
}