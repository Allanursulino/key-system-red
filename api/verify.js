import crypto from 'crypto';

// Database em memória (em produção use Redis)
const verificationDB = new Map();
const userActivityDB = new Map();
const fraudDetectionDB = new Map();

// Configurações
const CONFIG = {
    MAX_KEYS_PER_IP: 3,
    KEY_EXPIRY_HOURS: 24,
    COOLDOWN_MINUTES: 30,
    MAX_ATTEMPTS_PER_HOUR: 10,
    FRAUD_THRESHOLD: 5
};

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        const referer = req.headers['referer'] || '';
        
        console.log('=== 🔐 VERIFICATION REQUEST ===');
        console.log('IP:', clientIP);
        console.log('Referer:', referer);

        // ✅ ANTI-FRAUDE: Verificações de segurança
        const fraudCheck = await performFraudCheck(clientIP, userAgent, referer, req.query);
        
        if (!fraudCheck.allowed) {
            console.log('🚫 BLOCKED by Anti-Fraud:', fraudCheck.reason);
            
            await logFraudAttempt(clientIP, fraudCheck.reason, req.query);
            return sendBlockResponse(res, fraudCheck.reason);
        }

        // ✅ GERAR KEY SEGURA
        const keyData = generateSecureKey(clientIP, userAgent);
        
        console.log('✅ KEY GENERATED:', keyData.key);

        // ✅ ATUALIZAR ESTATÍSTICAS
        updateUserActivity(clientIP, keyData.key);

        // ✅ ENVIAR PARA DISCORD
        await sendVerificationAlert(clientIP, keyData, req.query);

        res.setHeader('Content-Type', 'application/json');
        res.status(200).json({
            success: true,
            key: keyData.key,
            expiresAt: keyData.expiresAt,
            expiresIn: '24 hours',
            message: 'Key generated successfully'
        });

    } catch (error) {
        console.error('❌ Verification API error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'System temporarily unavailable' 
        });
    }
}

// ✅ SISTEMA ANTI-FRAUDE
async function performFraudCheck(ip, userAgent, referer, queryParams) {
    const checks = {
        // 1. Verificação de IP
        ipNotBanned: !fraudDetectionDB.has(ip) || fraudDetectionDB.get(ip).score < CONFIG.FRAUD_THRESHOLD,
        
        // 2. Limite de tentativas
        withinAttemptLimit: await checkAttemptLimit(ip),
        
        // 3. Limite de keys por IP
        withinKeyLimit: await checkKeyLimit(ip),
        
        // 4. Cooldown respeitado
        cooldownRespected: await checkCooldown(ip),
        
        // 5. User Agent válido
        validUserAgent: userAgent && userAgent.length > 10 && !isSuspiciousUserAgent(userAgent),
        
        // 6. Referer válido (se veio de plataforma de verificação)
        validReferer: !referer || referer.includes('lootlabs.gg') || referer.includes('ogads.com'),
        
        // 7. Parâmetros válidos
        validParams: queryParams.verified === 'true' && queryParams.source
    };

    const passedChecks = Object.values(checks).filter(Boolean).length;
    const totalChecks = Object.keys(checks).length;
    
    console.log('🔐 Fraud Check Results:', checks);
    console.log('📊 Score:', passedChecks + '/' + totalChecks);

    if (passedChecks < 5) {
        return {
            allowed: false,
            reason: `Failed security checks (${passedChecks}/${totalChecks})`,
            score: passedChecks
        };
    }

    return { allowed: true, score: passedChecks };
}

// ✅ VERIFICAÇÃO DE LIMITE DE TENTATIVAS
async function checkAttemptLimit(ip) {
    const now = Date.now();
    const hourAgo = now - (60 * 60 * 1000);
    
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], keys: [] });
    }
    
    const userData = userActivityDB.get(ip);
    const recentAttempts = userData.attempts.filter(time => time > hourAgo);
    
    if (recentAttempts.length >= CONFIG.MAX_ATTEMPTS_PER_HOUR) {
        // Aumentar score de fraude
        incrementFraudScore(ip, 'Too many attempts');
        return false;
    }
    
    // Registrar tentativa
    userData.attempts.push(now);
    return true;
}

// ✅ VERIFICAÇÃO DE LIMITE DE KEYS
async function checkKeyLimit(ip) {
    if (!userActivityDB.has(ip)) return true;
    
    const userData = userActivityDB.get(ip);
    const activeKeys = userData.keys.filter(key => 
        verificationDB.has(key) && verificationDB.get(key).expiresAt > Date.now()
    );
    
    if (activeKeys.length >= CONFIG.MAX_KEYS_PER_IP) {
        incrementFraudScore(ip, 'Key limit exceeded');
        return false;
    }
    
    return true;
}

// ✅ VERIFICAÇÃO DE COOLDOWN
async function checkCooldown(ip) {
    if (!userActivityDB.has(ip)) return true;
    
    const userData = userActivityDB.get(ip);
    const lastKeyTime = Math.max(...userData.keys.map(key => 
        verificationDB.has(key) ? verificationDB.get(key).createdAt : 0
    ));
    
    const cooldownTime = CONFIG.COOLDOWN_MINUTES * 60 * 1000;
    
    if (Date.now() - lastKeyTime < cooldownTime) {
        incrementFraudScore(ip, 'Cooldown not respected');
        return false;
    }
    
    return true;
}

// ✅ DETECÇÃO DE USER AGENT SUSPEITO
function isSuspiciousUserAgent(userAgent) {
    const suspiciousPatterns = [
        /bot|curl|wget|scraper|spider|crawler/i,
        /python|java|php|node|go-http/i,
        /^Mozilla\/5.0 \(compatible; ?\)$/,
        /^$/,
        /unknown|test|fake/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
}

// ✅ INCREMENTAR SCORE DE FRAUDE
function incrementFraudScore(ip, reason) {
    if (!fraudDetectionDB.has(ip)) {
        fraudDetectionDB.set(ip, { score: 1, reasons: [reason], firstSeen: Date.now() });
    } else {
        const fraudData = fraudDetectionDB.get(ip);
        fraudData.score++;
        fraudData.reasons.push(reason);
        
        // Se score muito alto, banir IP
        if (fraudData.score >= CONFIG.FRAUD_THRESHOLD * 2) {
            console.log(`🚨 IP BANNED: ${ip} - Score: ${fraudData.score}`);
        }
    }
}

// ✅ GERAR KEY SEGURA
function generateSecureKey(ip, userAgent) {
    const key = crypto.randomBytes(16).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (CONFIG.KEY_EXPIRY_HOURS * 60 * 60 * 1000);
    
    // Salvar key no database
    verificationDB.set(key, {
        ip: ip,
        userAgent: userAgent,
        createdAt: Date.now(),
        expiresAt: expiresAt,
        uses: 0,
        isValid: true
    });
    
    return {
        key: key,
        expiresAt: expiresAt,
        createdAt: Date.now()
    };
}

// ✅ ATUALIZAR ATIVIDADE DO USUÁRIO
function updateUserActivity(ip, key) {
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], keys: [] });
    }
    
    const userData = userActivityDB.get(ip);
    userData.keys.push(key);
    
    // Manter apenas últimas 10 keys
    if (userData.keys.length > 10) {
        userData.keys = userData.keys.slice(-10);
    }
}

// ✅ LOG DE TENTATIVA DE FRAUDE
async function logFraudAttempt(ip, reason, queryParams) {
    console.log(`🚫 FRAUD ATTEMPT: ${ip} - ${reason}`);
    
    await sendToDiscord({
        title: "🚫 Fraud Attempt Blocked",
        description: `**IP:** ${ip}\n**Reason:** ${reason}\n**Params:** ${JSON.stringify(queryParams)}\n**Time:** ${new Date().toLocaleString()}`,
        color: 16711680
    });
}

// ✅ ENVIAR ALERTA DE VERIFICAÇÃO
async function sendVerificationAlert(ip, keyData, queryParams) {
    await sendToDiscord({
        title: "✅ Key Generated Successfully",
        description: `**Key:** ||${keyData.key}||\n**IP:** ${ip}\n**Platform:** ${queryParams.source || 'Direct'}\n**Expires:** ${new Date(keyData.expiresAt).toLocaleString()}`,
        color: 65280
    });
}

// ✅ RESPOSTA DE BLOQUEIO
function sendBlockResponse(res, reason) {
    res.status(403).json({
        success: false,
        error: 'ACCESS_DENIED',
        message: `Security violation detected: ${reason}`,
        code: 'ANTI_FRAUD_BLOCK'
    });
}

// ✅ WEBHOOK DISCORD
async function sendToDiscord(embedData) {
    try {
        await fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                embeds: [{
                    ...embedData,
                    timestamp: new Date().toISOString(),
                    footer: { text: "BoostKey Anti-Fraud System" }
                }]
            })
        });
    } catch (error) {
        console.log('⚠️ Discord webhook failed');
    }
}

// ✅ FUNÇÃO PARA VALIDAR KEY (usada por outros sistemas)
export function validateKey(key) {
    if (!verificationDB.has(key)) {
        return { valid: false, reason: 'Key not found' };
    }
    
    const keyData = verificationDB.get(key);
    
    if (!keyData.isValid) {
        return { valid: false, reason: 'Key revoked' };
    }
    
    if (Date.now() > keyData.expiresAt) {
        verificationDB.delete(key);
        return { valid: false, reason: 'Key expired' };
    }
    
    // Incrementar uso
    keyData.uses++;
    
    return {
        valid: true,
        data: {
            ip: keyData.ip,
            createdAt: keyData.createdAt,
            expiresAt: keyData.expiresAt,
            uses: keyData.uses
        }
    };
}

// ✅ LIMPEZA AUTOMÁTICA
setInterval(() => {
    const now = Date.now();
    let cleanedKeys = 0;
    let cleanedIPs = 0;
    
    // Limpar keys expiradas
    for (const [key, data] of verificationDB.entries()) {
        if (now > data.expiresAt) {
            verificationDB.delete(key);
            cleanedKeys++;
        }
    }
    
    // Limpar IPs antigos
    for (const [ip, data] of fraudDetectionDB.entries()) {
        if (now - data.firstSeen > 7 * 24 * 60 * 60 * 1000) { // 7 dias
            fraudDetectionDB.delete(ip);
            cleanedIPs++;
        }
    }
    
    if (cleanedKeys > 0 || cleanedIPs > 0) {
        console.log(`🧹 Cleaned ${cleanedKeys} expired keys and ${cleanedIPs} old IPs`);
    }
}, 60 * 60 * 1000); // A cada hora