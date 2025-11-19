import { validateKey } from './verify.js';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const key = req.query.key;
        
        if (!key) {
            return res.status(400).json({
                success: false,
                message: 'Key is required'
            });
        }

        const validation = validateKey(key);
        
        if (!validation.valid) {
            return res.status(403).json({
                success: false,
                message: validation.reason
            });
        }

        // ✅ FORMATO COMPATÍVEL COM WINDUI
        res.status(200).json({
            success: true,
            key: key, // Incluir a key na resposta
            message: 'Key is valid',
            data: {
                expires: validation.data.expiresAt,
                created: validation.data.createdAt
            }
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'System error: ' + error.message
        });
    }
}