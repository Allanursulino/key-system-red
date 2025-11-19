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
                error: 'KEY_REQUIRED',
                message: 'Key parameter is required'
            });
        }

        // ✅ VALIDAR KEY
        const validation = validateKey(key);
        
        if (!validation.valid) {
            return res.status(403).json({
                success: false,
                error: 'INVALID_KEY',
                message: validation.reason
            });
        }

        // ✅ KEY VÁLIDA - Retornar sucesso
        res.setHeader('Content-Type', 'application/json');
        res.status(200).json({
            success: true,
            message: 'Key is valid',
            data: {
                expiresAt: validation.data.expiresAt,
                uses: validation.data.uses,
                timeLeft: Math.max(0, validation.data.expiresAt - Date.now())
            }
        });

    } catch (error) {
        console.error('❌ Generate API error:', error);
        res.status(500).json({
            success: false,
            error: 'SYSTEM_ERROR'
        });
    }
}