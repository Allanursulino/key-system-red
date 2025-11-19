import crypto from 'crypto';

// Armazenar sessões ativas
const activeSessions = new Map();

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
    
    console.log('=== 🔍 ACCESS ATTEMPT ===');
    console.log('IP:', clientIP);
    console.log('Referer:', referer);
    console.log('User Agent:', userAgent.substring(0, 80));
    console.log('Query Params:', req.query);

    // ✅ CAMADA 1: Verificar se veio do LootLabs
    const isFromLootLabs = referer.includes('lootlabs.gg') || 
                           userAgent.includes('lootlabs') ||
                           req.query.source === 'lootlabs';

    // ✅ CAMADA 2: Verificar session token
    const sessionToken = req.query.session;
    const isValidSession = sessionToken && activeSessions.has(sessionToken);

    // ✅ CAMADA 3: Verificar approved IP
    const isApprovedIP = activeSessions.has(clientIP);

    console.log('🔐 Security Check:');
    console.log('  - From LootLabs:', isFromLootLabs);
    console.log('  - Valid Session:', isValidSession);
    console.log('  - Approved IP:', isApprovedIP);

    // ❌ BLOQUEAR ACESSO DIRETO
    if (!isFromLootLabs && !isValidSession && !isApprovedIP) {
      console.log('🚫 BLOCKED: Direct access detected');
      
      // Webhook Discord para tentativa de acesso direto
      fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          embeds: [{
            title: "🚫 Blocked Direct Access",
            description: `**IP:** ${clientIP}\n**Referer:** ${referer || 'None'}\n**Time:** ${new Date().toLocaleString()}`,
            color: 16711680,
            timestamp: new Date().toISOString(),
            footer: { text: "Security System • Blocked" }
          }]
        })
      }).catch(console.error);

      return res.status(403).send('ACCESS DENIED: Please complete LootLabs verification first. Visit the homepage and click the verification button.');
    }

    // ✅ APROVAR E GERAR KEY
    console.log('✅ ACCESS GRANTED - Generating key...');

    // Criar/atualizar sessão
    if (!activeSessions.has(clientIP)) {
      activeSessions.set(clientIP, {
        firstAccess: Date.now(),
        lastAccess: Date.now(),
        accessCount: 1,
        keysGenerated: 1
      });
    } else {
      const session = activeSessions.get(clientIP);
      session.lastAccess = Date.now();
      session.accessCount++;
      session.keysGenerated++;
    }

    // Gerar key
    const key = crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    
    console.log('🔑 Key generated:', key);

    // ✅ WEBHOOK SUCESSO
    fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: "✅ Key Generated Successfully",
          description: `**Key:** ||${key}||\n**IP:** ${clientIP}\n**Source:** ${isFromLootLabs ? 'LootLabs' : isValidSession ? 'Session' : 'Approved IP'}\n**Time:** ${new Date().toLocaleString()}`,
          color: 65280,
          timestamp: new Date().toISOString(),
          footer: { text: "Key System • Verified Access" }
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

// Limpar sessões antigas (24 horas)
setInterval(() => {
  const now = Date.now();
  const dayInMs = 24 * 60 * 60 * 1000;
  let cleaned = 0;
  
  for (const [ip, session] of activeSessions.entries()) {
    if (now - session.firstAccess > dayInMs) {
      activeSessions.delete(ip);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned ${cleaned} old sessions`);
  }
}, 60 * 60 * 1000);