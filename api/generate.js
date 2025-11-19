import crypto from 'crypto';

// Armazenar IPs aprovados (24 horas)
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
    
    console.log('🔍 Access attempt:', {
      ip: clientIP,
      referer: referer,
      userAgent: userAgent.substring(0, 50) + '...'
    });

    // ✅ VERIFICAÇÕES DE SEGURANÇA
    const securityChecks = {
      // 1. Veio do LootLabs via Success URL
      fromSuccessURL: req.query.approved === 'true',
      
      // 2. Referer é do LootLabs
      fromLootLabsReferer: referer.includes('lootlabs.gg'),
      
      // 3. IP já foi aprovado antes
      isApprovedIP: approvedIPs.has(clientIP),
      
      // 4. User Agent parece legítimo (não é bot)
      isLikelyHuman: !userAgent.includes('bot') && 
                    !userAgent.includes('Bot') && 
                    !userAgent.includes('curl')
    };

    console.log('🔐 Security checks:', securityChecks);

    // ✅ CALCULAR PONTUAÇÃO DE SEGURANÇA
    const securityScore = Object.values(securityChecks).filter(Boolean).length;
    
    // ❌ BLOQUEAR: Pontuação muito baixa (acesso direto)
    if (securityScore < 2) {
      console.log('🚫 BLOCKED: Low security score - Direct access detected');
      return res.status(403).send('ACCESS DENIED: Please complete LootLabs tasks first. Visit the homepage and click the button.');
    }

    // ✅ APROVAR IP POR 24 HORAS
    if (!approvedIPs.has(clientIP)) {
      approvedIPs.set(clientIP, {
        firstApproved: Date.now(),
        lastAccess: Date.now(),
        accessCount: 1,
        userAgent: userAgent
      });
      console.log('✅ New IP approved:', clientIP);
    } else {
      // Atualizar IP existente
      const ipData = approvedIPs.get(clientIP);
      ipData.lastAccess = Date.now();
      ipData.accessCount++;
    }

    // ✅ GERAR KEY
    console.log('🔑 Generating key for approved access...');
    
    const key = crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    
    console.log('✅ Key generated:', key);

    // 📨 WEBHOOK DISCORD
    fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: "🔑 New 24h Key Generated",
          description: `**Key:** ||${key}||\n**IP:** ${clientIP}\n**Security Score:** ${securityScore}/4\n**Method:** ${securityChecks.fromSuccessURL ? 'Success URL' : securityChecks.fromLootLabsReferer ? 'LootLabs Referer' : 'Approved IP'}`,
          color: 16711680,
          timestamp: new Date().toISOString(),
          footer: { text: "Key System • Smart Protection" }
        }]
      })
    }).catch(error => {
      console.log('⚠️ Discord webhook failed:', error.message);
    });

    // 🧹 Limpar IPs antigos (mais de 24 horas)
    cleanupOldIPs();

    res.setHeader('Content-Type', 'text/plain');
    res.send(key);

  } catch (error) {
    console.error('❌ Generate API error:', error);
    res.status(500).send('ERROR: Failed to generate key');
  }
}

// Limpar IPs com mais de 24 horas
function cleanupOldIPs() {
  const now = Date.now();
  const twentyFourHours = 24 * 60 * 60 * 1000;
  
  for (const [ip, data] of approvedIPs.entries()) {
    if (now - data.firstApproved > twentyFourHours) {
      approvedIPs.delete(ip);
    }
  }
}

// Limpar a cada hora
setInterval(cleanupOldIPs, 60 * 60 * 1000);