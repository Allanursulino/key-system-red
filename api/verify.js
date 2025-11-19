import crypto from 'crypto';

// Database em memória
const verificationDB = new Map();
const userActivityDB = new Map();
const validKeysDB = new Map();

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
        const { key } = req.query;

        console.log('=== 🔐 VERIFY API ===');
        console.log('IP:', clientIP);
        console.log('Key:', key);
        console.log('All query params:', req.query);

        // ✅ VALIDAR KEY EXISTENTE (para o WindUI)
        if (key) {
            console.log('🔑 Validating existing key...');
            
            // Verificação de segurança básica
            if (!key || key.length !== 32) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid key format'
                });
            }

            const validation = validateKey(key);
            
            if (!validation.valid) {
                return res.status(403).json({
                    success: false,
                    message: validation.reason
                });
            }

            console.log('✅ Key validated successfully:', key);
            
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

        // ❌ Se não tem key parameter
        console.log('❌ No key parameter provided');
        return res.status(400).json({
            success: false,
            message: 'Key parameter is required'
        });

    } catch (error) {
        console.error('❌ Error in verify API:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
}

// ✅ GERAR NOVA KEY (para o site)
export function generateNewKey(ip, userAgent) {
    const key = crypto.randomBytes(16).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (CONFIG.KEY_EXPIRY_HOURS * 60 * 60 * 1000);
    
    // Salvar no banco
    validKeysDB.set(key, {
        ip: ip,
        userAgent: userAgent,
        createdAt: Date.now(),
        expiresAt: expiresAt,
        uses: 0,
        isValid: true
    });
    
    // Registrar no usuário
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], keys: [] });
    }
    userActivityDB.get(ip).keys.push(key);
    
    console.log('🔑 NEW KEY GENERATED:', key, 'for IP:', ip);
    
    return { key, expiresAt };
}

// ✅ VALIDAR KEY
function validateKey(key) {
    console.log('🔍 Checking key in database:', key);
    
    if (!validKeysDB.has(key)) {
        console.log('❌ Key not found in database');
        return { valid: false, reason: 'Key not found' };
    }
    
    const keyData = validKeysDB.get(key);
    console.log('📋 Key data found:', keyData);
    
    if (!keyData.isValid) {
        return { valid: false, reason: 'Key revoked' };
    }
    
    if (Date.now() > keyData.expiresAt) {
        validKeysDB.delete(key);
        return { valid: false, reason: 'Key expired' };
    }
    
    keyData.uses += 1;
    console.log('✅ Key is valid. Uses:', keyData.uses);
    
    return {
        valid: true,
        expiresAt: keyData.expiresAt,
        createdAt: keyData.createdAt,
        uses: keyData.uses
    };
}

// ✅ OBTER TODAS AS KEYS (para debug)
export function getAllKeys() {
    return Array.from(validKeysDB.entries());
}

// Limpeza automática
setInterval(() => {
    const now = Date.now();
    let expiredCount = 0;
    
    for (const [key, data] of validKeysDB.entries()) {
        if (now > data.expiresAt) {
            validKeysDB.delete(key);
            expiredCount++;
        }
    }
    
    if (expiredCount > 0) {
        console.log(`🧹 Cleaned ${expiredCount} expired keys`);
    }
}, 30 * 60 * 1000);