import { generateNewKey, validateKey } from './verify.js';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
        const userAgent = req.headers['user-agent'] || '';
        const { key, verified, platform } = req.query;

        console.log('=== 🔑 GENERATE API ===');
        console.log('IP:', clientIP);
        console.log('Query params:', req.query);

        // ✅ GERAR NOVA KEY (quando usuário completa LootLabs)
        if (verified === 'true' && platform === 'lootlabs') {
            console.log('🎮 Generating new key after LootLabs verification');
            
            // Verificar se já tem key ativa
            const existingKey = await getActiveKeyForIP(clientIP);
            if (existingKey) {
                console.log('ℹ️ Returning existing key:', existingKey.key);
                return res.status(200).json({
                    success: true,
                    key: existingKey.key,
                    expiresAt: existingKey.expiresAt,
                    existing: true
                });
            }

            // Gerar nova key
            const keyData = generateNewKey(clientIP, userAgent);
            
            console.log('✅ New key generated:', keyData.key);
            
            return res.status(200).json({
                success: true,
                key: keyData.key,
                expiresAt: keyData.expiresAt,
                expiresIn: '24 hours',
                existing: false
            });
        }

        // ✅ VALIDAR KEY EXISTENTE (fallback)
        if (key) {
            console.log('🔑 Validating key in generate endpoint:', key);
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
                data: {
                    expiresAt: validation.expiresAt,
                    createdAt: validation.createdAt,
                    uses: validation.uses
                }
            });
        }

        console.log('❌ Invalid parameters');
        return res.status(400).json({
            success: false,
            message: 'Invalid parameters'
        });

    } catch (error) {
        console.error('❌ Error in generate API:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}

// ✅ BUSCAR KEY ATIVA
async function getActiveKeyForIP(ip) {
    if (!verificationDB.has(ip)) return null;
    
    const userData = verificationDB.get(ip);
    const now = Date.now();
    
    for (const key of userData.keys) {
        const keyData = validateKey(key);
        if (keyData.valid) {
            return {
                key: key,
                expiresAt: keyData.expiresAt
            };
        }
    }
    return null;
}