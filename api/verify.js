import crypto from 'crypto';

// Database em memória
const verificationDB = new Map();
const userActivityDB = new Map();
const validKeysDB = new Map();
const pendingVerifications = new Map(); // Novas verificações pendentes

// Configurações
const CONFIG = {
    MAX_KEYS_PER_IP: 1,
    KEY_EXPIRY_HOURS: 24,
    COOLDOWN_MINUTES: 5,
    MAX_ATTEMPTS_PER_HOUR: 10
};

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
        const { key, precheck, verified, platform, verification_id } = req.query;

        console.log('=== 🔐 VERIFY API ===');
        console.log('IP:', clientIP);
        console.log('Query:', req.query);

        // ✅ PRECHECK - Verificação antes de iniciar
        if (precheck === 'true') {
            const securityCheck = await performPreCheck(clientIP);
            
            if (!securityCheck.allowed) {
                return res.status(403).json({
                    success: false,
                    message: securityCheck.reason
                });
            }

            // Criar verificação pendente
            const verificationId = generateVerificationId();
            pendingVerifications.set(verificationId, {
                ip: clientIP,
                createdAt: Date.now(),
                completed: false
            });

            return res.status(200).json({
                success: true,
                message: 'Pre-check approved',
                verification_id: verificationId
            });
        }

        // ✅ VERIFICAR SE COMPLETOU NO LOOTLABS
        if (verification_id && verified === 'true') {
            const pendingVerification = pendingVerifications.get(verification_id);
            
            if (!pendingVerification) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid verification session'
                });
            }

            if (pendingVerification.ip !== clientIP) {
                return res.status(403).json({
                    success: false,
                    message: 'IP mismatch'
                });
            }

            // Marcar como completada
            pendingVerification.completed = true;
            pendingVerification.completedAt = Date.now();

            // Verificar se já tem key ativa
            const existingKey = await getActiveKeyForIP(clientIP);
            if (existingKey) {
                return res.status(200).json({
                    success: true,
                    key: existingKey.key,
                    expiresAt: existingKey.expiresAt,
                    existing: true
                });
            }

            // Gerar nova key APENAS se completou a verificação
            const keyData = generateSecureKey(clientIP);
            
            // Limpar verificação pendente
            pendingVerifications.delete(verification_id);
            
            return res.status(200).json({
                success: true,
                key: keyData.key,
                expiresAt: keyData.expiresAt,
                expiresIn: '24 hours',
                existing: false
            });
        }

        // ✅ VALIDAR KEY EXISTENTE
        if (key) {
            const validation = validateKey(key);
            
            if (!validation.valid) {
                return res.status(403).json({
                    success: false,
                    message: validation.reason
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Key valid',
                key: key,
                data: {
                    expiresAt: validation.expiresAt,
                    createdAt: validation.createdAt,
                    uses: validation.uses
                }
            });
        }

        return res.status(400).json({
            success: false,
            message: 'Invalid parameters'
        });

    } catch (error) {
        console.error('❌ Error in verify API:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
}

// ✅ GERAR ID DE VERIFICAÇÃO
function generateVerificationId() {
    return crypto.randomBytes(8).toString('hex');
}

// ✅ PRÉ-VERIFICAÇÃO
async function performPreCheck(ip) {
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], keys: [], prechecks: [] });
    }
    
    const userData = userActivityDB.get(ip);
    const hourAgo = Date.now() - (60 * 60 * 1000);
    const recentPrechecks = userData.prechecks.filter(time => time > hourAgo);
    
    if (recentPrechecks.length >= 3) {
        return { allowed: false, reason: 'Too many verification attempts' };
    }
    
    userData.prechecks.push(Date.now());
    return { allowed: true };
}

// ✅ GERAR KEY SEGURA
function generateSecureKey(ip) {
    const key = crypto.randomBytes(16).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (CONFIG.KEY_EXPIRY_HOURS * 60 * 60 * 1000);
    
    validKeysDB.set(key, {
        ip: ip,
        createdAt: Date.now(),
        expiresAt: expiresAt,
        uses: 0,
        isValid: true
    });
    
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], keys: [], prechecks: [] });
    }
    userActivityDB.get(ip).keys.push(key);
    
    console.log('🔑 NEW KEY GENERATED:', key, 'for IP:', ip);
    
    return { key, expiresAt };
}

// ✅ BUSCAR KEY ATIVA
async function getActiveKeyForIP(ip) {
    if (!userActivityDB.has(ip)) return null;
    
    const userData = userActivityDB.get(ip);
    const now = Date.now();
    
    for (const key of userData.keys) {
        if (validKeysDB.has(key)) {
            const keyData = validKeysDB.get(key);
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

// ✅ VALIDAR KEY
function validateKey(key) {
    if (!validKeysDB.has(key)) {
        return { valid: false, reason: 'Key not found' };
    }
    
    const keyData = validKeysDB.get(key);
    
    if (!keyData.isValid) {
        return { valid: false, reason: 'Key revoked' };
    }
    
    if (Date.now() > keyData.expiresAt) {
        validKeysDB.delete(key);
        return { valid: false, reason: 'Key expired' };
    }
    
    keyData.uses += 1;
    return {
        valid: true,
        expiresAt: keyData.expiresAt,
        createdAt: keyData.createdAt,
        uses: keyData.uses
    };
}

// ✅ LIMPEZA AUTOMÁTICA (incluindo verificações pendentes expiradas)
setInterval(() => {
    const now = Date.now();
    let expiredCount = 0;
    let pendingExpired = 0;
    
    // Limpar keys expiradas
    for (const [key, data] of validKeysDB.entries()) {
        if (now > data.expiresAt) {
            validKeysDB.delete(key);
            expiredCount++;
        }
    }
    
    // Limpar verificações pendentes expiradas (10 minutos)
    for (const [id, data] of pendingVerifications.entries()) {
        if (now - data.createdAt > 10 * 60 * 1000) { // 10 minutos
            pendingVerifications.delete(id);
            pendingExpired++;
        }
    }
    
    if (expiredCount > 0 || pendingExpired > 0) {
        console.log(`🧹 Cleaned ${expiredCount} expired keys and ${pendingExpired} pending verifications`);
    }
}, 5 * 60 * 1000); // A cada 5 minutos