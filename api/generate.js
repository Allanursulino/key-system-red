import crypto from 'crypto';

// SECRET KEY - Só o LootLabs sabe essa chave
const SECRET_KEY = "LOOTLABS123";
const approvedIPs = new Map();

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
    
    console.log('🔍 Access attempt from:', clientIP);
    console.log('📧 Query params:', req.query);

    // ✅ VERIFICAÇÃO PRINCIPAL: SECRET KEY
    const hasValidSecret = req.query.secret === SECRET_KEY;
    const hasApprovedParam = req.query.approved === 'true';

    // ✅ VERIFICAÇÕES SECUNDÁRIAS
    const securityChecks = {
      validSecret: hasValidSecret, // ✅ CHAVE SECRETA CORRETA
      approvedParam: hasApprovedParam,
      fromLootLabsReferer: referer.includes('lootlabs.gg'),
      isApprovedIP: approvedIPs.has(clientIP),
      isLikelyHuman: !userAgent.includes('bot') && !userAgent.includes('curl')
    };

    console.log('🔐 Security checks:', securityChecks);

    // ✅ SE TEM A SECRET KEY, APROVA AUTOMATICAMENTE
    if (securityChecks.validSecret) {
      console.log('✅ VALID SECRET KEY - Approving access');
      
      // Marcar IP como aprovado
      if (!approvedIPs.has(clientIP)) {
        approvedIPs.set(clientIP, {
          firstApproved: Date.now(),
          lastAccess: Date.now(),
          approvedBy: 'SECRET_KEY'
        });
      }

      // ✅ GERAR KEY
      const key = crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{4}/g).join('-');
      console.log('🔑 Key generated:', key);

      // 📨 DISCORD WEBHOOK
      fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          embeds: [{
            title: "🔑 Key Generated (Secret Valid)",
            description: `**Key:** ||${key}||\n**IP:** ${clientIP}\n**Method:** Secret Key Validation\n**Time:** ${new Date().toLocaleString()}`,
            color: 16711680,
            timestamp: new Date().toISOString(),
            footer: { text: "Key System • Secret Key Protection" }
          }]
        })
      }).catch(console.error);

      res.setHeader('Content-Type', 'text/plain');
      return res.send(key);
    }

    // ❌ BLOQUEAR SE NÃO TEM SECRET KEY
    console.log('🚫 BLOCKED: No valid secret key');
    console.log('💡 Expected:', SECRET_KEY, 'Received:', req.query.secret);
    
    res.status(403).send('ACCESS DENIED: Please complete LootLabs tasks first. Visit the homepage and click the button.');

  } catch (error) {
    console.error('❌ Generate API error:', error);
    res.status(500).send('ERROR: Failed to generate key');
  }
}

// Limpar IPs antigos
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of approvedIPs.entries()) {
    if (now - data.firstApproved > 24 * 60 * 60 * 1000) {
      approvedIPs.delete(ip);
    }
  }
}, 60 * 60 * 1000);