import crypto from 'crypto';

// Database em memória
const verificationDB = new Map();
const userActivityDB = new Map();
const pendingVerifications = new Map();

// Configurações
const CONFIG = {
    MAX_KEYS_PER_IP: 3,
    KEY_EXPIRY_HOURS: 24,
    COOLDOWN_MINUTES: 30,
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
        const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        const referer = req.headers['referer'] || '';
        
        console.log('=== 🔐 VERIFICATION ===');
        console.log('IP:', clientIP);
        console.log('Referer:', referer);
        console.log('Query:', req.query);

        // ✅ PRÉ-VERIFICAÇÃO (antes do LootLabs)
        if (req.query.action === 'start') {
            console.log('✅ Starting verification process');
            
            // Registrar verificação pendente
            pendingVerifications.set(clientIP, {
                startedAt: Date.now(),
                userAgent: userAgent
            });
            
            return res.status(200).json({
                success: true,
                message: 'Verification process started'
            });
        }

        // ✅ PÓS-VERIFICAÇÃO (depois do LootLabs)
        if (req.query.action === 'complete' && req.query.verified === 'true') {
            console.log('✅ Completing verification');
            
            // Verificar se há verificação pendente
            if (!pendingVerifications.has(clientIP)) {
                return res.status(400).json({
                    success: false,
                    error: 'NO_PENDING_VERIFICATION',
                    message: 'Please start verification first'
                });
            }

            // ✅ GERAR KEY
            const keyData = generateSecureKey(clientIP, userAgent);
            console.log('✅ KEY GENERATED:', keyData.key);

            // ✅ LIMPAR verificação pendente
            pendingVerifications.delete(clientIP);

            // ✅ ATUALIZAR ESTATÍSTICAS
            updateUserActivity(clientIP, keyData.key);

            return res.status(200).json({
                success: true,
                key: keyData.key,
                expiresAt: keyData.expiresAt,
                expiresIn: '24 hours',
                message: 'Key generated successfully'
            });
        }

        // ❌ REQUISIÇÃO INVÁLIDA
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
    for (const [ip, data] of pendingVerifications.entries()) {
        if (now - data.startedAt > 10 * 60 * 1000) { // 10 minutos
            pendingVerifications.delete(ip);
        }
    }
}, 60 * 60 * 1000);