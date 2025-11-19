import { verificationDB, userActivityDB, fraudDetectionDB } from './verify.js';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const now = Date.now();
        const dayAgo = now - (24 * 60 * 60 * 1000);
        
        // ✅ CALCULAR ESTATÍSTICAS
        const stats = {
            // Keys
            totalKeys: verificationDB.size,
            activeKeys: Array.from(verificationDB.values()).filter(key => key.expiresAt > now).length,
            expiredKeys: Array.from(verificationDB.values()).filter(key => key.expiresAt <= now).length,
            
            // Usuários
            uniqueIPs: new Set(Array.from(verificationDB.values()).map(key => key.ip)).size,
            activeUsers: Array.from(userActivityDB.entries()).filter(([ip, data]) => 
                data.keys.some(key => verificationDB.has(key) && verificationDB.get(key).expiresAt > now)
            ).length,
            
            // Fraude
            blockedIPs: Array.from(fraudDetectionDB.entries()).filter(([ip, data]) => 
                data.score >= 5
            ).length,
            totalFraudAttempts: Array.from(fraudDetectionDB.values()).reduce((sum, data) => sum + data.score, 0),
            
            // Performance
            successRate: calculateSuccessRate(),
            averageUses: calculateAverageUses()
        };

        res.setHeader('Content-Type', 'application/json');
        res.status(200).json({
            success: true,
            data: stats,
            timestamp: now
        });

    } catch (error) {
        console.error('❌ Stats API error:', error);
        res.status(500).json({
            success: false,
            error: 'STATS_ERROR'
        });
    }
}

function calculateSuccessRate() {
    const totalAttempts = Array.from(userActivityDB.values()).reduce((sum, data) => 
        sum + data.attempts.length, 0
    );
    const totalKeys = verificationDB.size;
    
    if (totalAttempts === 0) return 100;
    return Math.round((totalKeys / totalAttempts) * 100);
}

function calculateAverageUses() {
    const keys = Array.from(verificationDB.values());
    if (keys.length === 0) return 0;
    
    const totalUses = keys.reduce((sum, key) => sum + key.uses, 0);
    return (totalUses / keys.length).toFixed(2);
}