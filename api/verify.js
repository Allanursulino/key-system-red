import crypto from 'crypto';

// Database em memória
const verificationDB = new Map();
const userActivityDB = new Map();
const fraudDetectionDB = new Map();
const pendingVerifications = new Map();

// Configurações
const CONFIG = {
    MAX_KEYS_PER_IP: 3,
    KEY_EXPIRY_HOURS: 24,
    COOLDOWN_MINUTES: 30,
    MAX_ATTEMPTS_PER_HOUR: 10,
    FRAUD_THRESHOLD: 5,
    VERIFICATION_TIMEOUT: 5 * 60 * 1000
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

        // ✅ VERIFICAÇÃO ÚNICA
        if (pendingVerifications.has(clientIP)) {
            const pending = pendingVerifications.get(clientIP);
            if (Date.now() - pending.startedAt < CONFIG.VERIFICATION_TIMEOUT) {
                console.log('🚫 BLOCKED: Verification already in progress');
                return res.status(429).json({
                    success: false,
                    error: 'VERIFICATION_IN_PROGRESS',
                    message: 'Please complete your current verification first'
                });
            } else {
                pendingVerifications.delete(clientIP);
            }
        }

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

        // ✅ PRÉ-VERIFICAÇÃO
        if (req.query.precheck === 'true') {
            console.log('✅ Pre-check passed - Starting LootLabs verification');
            
            pendingVerifications.set(clientIP, {
                startedAt: Date.now(),
                userAgent: userAgent,
                platform: req.query.platform
            });
            
            return res.status(200).json({
                success: true,
                message: 'Pre-check successful'
            });
        }

        // ✅ PÓS-VERIFICAÇÃO
        if (req.query.verified === 'true' && req.query.platform === 'lootlabs') {
            if (!pendingVerifications.has(clientIP)) {
                console.log('🚫 BLOCKED: No pending verification found');
                return res.status(403).json({
                    success: false,
                    error: 'NO_PENDING_VERIFICATION',
                    message: 'Please start verification from homepage'
                });
            }

            const keyData = generateSecureKey(clientIP, userAgent);
            console.log('✅ SINGLE KEY GENERATED:', keyData.key);

            pendingVerifications.delete(clientIP);
            updateUserActivity(clientIP, keyData.key);

            // Webhook Discord
            await sendToDiscord({
                title: "✅ Key Generated",
                description: `**Key:** ||${keyData.key}||\n**IP:** ${clientIP}\n**Time:** ${new Date().toLocaleString()}`,
                color: 65280
            });

            return res.status(200).json({
                success: true,
                key: keyData.key,
                expiresAt: keyData.expiresAt,
                expiresIn: '24 hours'
            });
        }

        return res.status(400).json({
            success: false,
            error: 'INVALID_REQUEST'
        });

    } catch (error) {
        console.error('❌ Verify API error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'SYSTEM_ERROR' 
        });
    }
}

// Funções Anti-Fraude
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
}

async function logFraudAttempt(ip, reason, queryParams) {
    console.log(`🚫 FRAUD: ${ip} - ${reason}`);
    await sendToDiscord({
        title: "🚫 Fraud Blocked",
        description: `**IP:** ${ip}\n**Reason:** ${reason}\n**Time:** ${new Date().toLocaleString()}`,
        color: 16711680
    });
}

async function sendToDiscord(embedData) {
    try {
        await fetch("https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                embeds: [{
                    ...embedData,
                    timestamp: new Date().toISOString(),
                    footer: { text: "MultiHub Key System" }
                }]
            })
        });
    } catch (error) {
        console.log('⚠️ Discord webhook failed');
    }
}

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
    let cleaned = 0;
    
    for (const [key, data] of verificationDB.entries()) {
        if (now > data.expiresAt) {
            verificationDB.delete(key);
            cleaned++;
        }
    }
    
    for (const [ip, data] of pendingVerifications.entries()) {
        if (now - data.startedAt > CONFIG.VERIFICATION_TIMEOUT) {
            pendingVerifications.delete(ip);
        }
    }
    
    if (cleaned > 0) console.log(`🧹 Cleaned ${cleaned} expired keys`);
}, 60 * 60 * 1000);