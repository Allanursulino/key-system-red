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
        const { key } = req.query;

        console.log('=== 🔑 API GENERATE ===');
        console.log('IP:', clientIP);
        console.log('Key:', key);

        if (key) {
            // ✅ VALIDAR KEY EXISTENTE
            const validation = validateKey(key);
            
            if (!validation.valid) {
                return res.status(403).json({
                    success: false,
                    message: validation.reason
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Key válida',
                data: {
                    expiresAt: validation.expiresAt,
                    createdAt: validation.createdAt,
                    uses: validation.uses
                }
            });
        } else {
            // ✅ GERAR NOVA KEY
            const keyData = generateNewKey(clientIP, userAgent);
            
            return res.status(200).json({
                success: true,
                message: 'Nova key gerada',
                key: keyData.key,
                expiresAt: keyData.expiresAt,
                expiresIn: '24 horas'
            });
        }

    } catch (error) {
        console.error('❌ Erro na API generate:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
}