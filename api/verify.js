import crypto from 'crypto';

// Database em memória
const verificationDB = new Map();
const userActivityDB = new Map();
const fraudDetectionDB = new Map();

// Configurações ATUALIZADAS - APENAS 1 KEY POR IP
const CONFIG = {
    MAX_KEYS_PER_IP: 1, // MUDADO DE 3 PARA 1
    KEY_EXPIRY_HOURS: 24,
    COOLDOWN_MINUTES: 30,
    MAX_ATTEMPTS_PER_HOUR: 5,
    FRAUD_THRESHOLD: 3
};

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
        
        console.log('=== 🔐 VERIFICATION ===');
        console.log('IP:', clientIP);
        console.log('Referer:', referer);

        // ✅ ANTI-FRAUDE
        const fraudCheck = await performFraudCheck(clientIP, userAgent, referer, req.query);
        
        if (!fraudCheck.allowed) {
            console.log('🚫 BLOCKED:', fraudCheck.reason);
            await logFraudAttempt(clientIP, fraudCheck.reason, req.query);
            return res.status(403).json({
                success: false,
                error: 'ACCESS_DENIED',
                message: fraudCheck.reason
            });
        }

        // ✅ VERIFICAR SE JÁ EXISTE KEY ATIVA PARA ESTE IP
        const existingKey = await getActiveKeyForIP(clientIP);
        if (existingKey) {
            console.log('ℹ️ Returning existing key for IP:', clientIP);
            return res.status(200).json({
                success: true,
                key: existingKey.key,
                expiresAt: existingKey.expiresAt,
                expiresIn: '24 hours',
                existing: true
            });
        }

        // ✅ GERAR NOVA KEY
        const keyData = generateSecureKey(clientIP, userAgent);
        console.log('✅ NEW KEY GENERATED:', keyData.key);

        // ✅ ATUALIZAR ESTATÍSTICAS
        updateUserActivity(clientIP, keyData.key);

        res.setHeader('Content-Type', 'application/json');
        res.status(200).json({
            success: true,
            key: keyData.key,
            expiresAt: keyData.expiresAt,
            expiresIn: '24 hours',
            existing: false
        });

    } catch (error) {
        console.error('❌ Verify API error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'SYSTEM_ERROR' 
        });
    }
}

// ✅ NOVA FUNÇÃO: Buscar key ativa existente para o IP
async function getActiveKeyForIP(ip) {
    if (!userActivityDB.has(ip)) return null;
    
    const userData = userActivityDB.get(ip);
    const now = Date.now();
    
    // Procurar por keys ativas deste IP
    for (const key of userData.keys) {
        if (verificationDB.has(key)) {
            const keyData = verificationDB.get(key);
            if (keyData.expiresAt > now && keyData.isValid) {
                return {
                    key: key,
                    expiresAt: keyData.expiresAt
                };
            }
        }
    }
    return null;
}

async function performFraudCheck(ip, userAgent, referer, queryParams) {
    const checks = {
        ipNotBanned: !fraudDetectionDB.has(ip) || fraudDetectionDB.get(ip).score < CONFIG.FRAUD_THRESHOLD,
        withinAttemptLimit: await checkAttemptLimit(ip),
        withinKeyLimit: await checkKeyLimit(ip),
        cooldownRespected: await checkCooldown(ip),
        validUserAgent: userAgent && userAgent.length > 10,
        validReferer: !referer || referer.includes('lootlabs.gg'),
        validParams: queryParams.verified === 'true' && queryParams.platform === 'lootlabs'
    };

    const passedChecks = Object.values(checks).filter(Boolean).length;
    
    if (passedChecks < 5) {
        return {
            allowed: false,
            reason: `Failed security checks (${passedChecks}/7)`
        };
    }

    return { allowed: true };
}

async function checkAttemptLimit(ip) {
    if (!userActivityDB.has(ip)) return true;
    const userData = userActivityDB.get(ip);
    const hourAgo = Date.now() - (60 * 60 * 1000);
    const recentAttempts = userData.attempts.filter(time => time > hourAgo);
    return recentAttempts.length < CONFIG.MAX_ATTEMPTS_PER_HOUR;
}

async function checkKeyLimit(ip) {
    if (!userActivityDB.has(ip)) return true;
    const userData = userActivityDB.get(ip);
    const activeKeys = userData.keys.filter(key => 
        verificationDB.has(key) && verificationDB.get(key).expiresAt > Date.now()
    );
    return activeKeys.length < CONFIG.MAX_KEYS_PER_IP;
}

async function checkCooldown(ip) {
    if (!userActivityDB.has(ip)) return true;
    const userData = userActivityDB.get(ip);
    const lastKeyTime = Math.max(...userData.keys.map(key => 
        verificationDB.has(key) ? verificationDB.get(key).createdAt : 0
    ));
    return Date.now() - lastKeyTime > (CONFIG.COOLDOWN_MINUTES * 60 * 1000);
}

function generateSecureKey(ip, userAgent) {
    const key = crypto.randomBytes(16).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (CONFIG.KEY_EXPIRY_HOURS * 60 * 60 * 1000);
    
    verificationDB.set(key, {
        ip: ip,
        userAgent: userAgent,
        createdAt: Date.now(),
        expiresAt: expiresAt,
        uses: 0,
        isValid: true
    });
    
    return { key, expiresAt };
}

function updateUserActivity(ip, key) {
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], keys: [] });
    }
    const userData = userActivityDB.get(ip);
    userData.keys.push(key);
    userData.attempts.push(Date.now());
}

async function logFraudAttempt(ip, reason, queryParams) {
    console.log(`🚫 FRAUD: ${ip} - ${reason}`);
    if (!fraudDetectionDB.has(ip)) {
        fraudDetectionDB.set(ip, { score: 1, lastAttempt: Date.now() });
    } else {
        const fraudData = fraudDetectionDB.get(ip);
        fraudData.score++;
        fraudData.lastAttempt = Date.now();
    }
}

// Export para outras APIs
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

// Limpeza automática
setInterval(() => {
    const now = Date.now();
    for (const [key, data] of verificationDB.entries()) {
        if (now > data.expiresAt) {
            verificationDB.delete(key);
        }
    }
}, 60 * 60 * 1000);