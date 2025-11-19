import { verificationDB, userActivityDB } from './verify.js';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const now = Date.now();
        
        const stats = {
            totalKeys: verificationDB.size,
            activeKeys: Array.from(verificationDB.values()).filter(key => key.expiresAt > now).length,
            uniqueIPs: new Set(Array.from(verificationDB.values()).map(key => key.ip)).size,
            activeUsers: Array.from(userActivityDB.entries()).filter(([ip, data]) => 
                data.keys.some(key => verificationDB.has(key) && verificationDB.get(key).expiresAt > now)
            ).length,
        };

        res.status(200).json({
            success: true,
            data: stats
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'STATS_ERROR'
        });
    }
}