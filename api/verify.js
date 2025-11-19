import crypto from 'crypto';

// Database em memória
const verificationDB = new Map();
const userActivityDB = new Map();
const fraudDetectionDB = new Map();

// Configurações ATUALIZADAS
const CONFIG = {
    MAX_KEYS_PER_IP: 1,
    KEY_EXPIRY_HOURS: 24,
    COOLDOWN_MINUTES: 5,
    MAX_ATTEMPTS_PER_HOUR: 20,
    FRAUD_THRESHOLD: 10,
    WEBHOOK_URL: 'https://discord.com/api/webhooks/1426304674595737734/Ii0NoDtSTbdLeQP-SZ4xwgc4m99mrOXTrPv_o2Wugqmg0nuM5fOLw9x1llRca4D5QCUH'
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
        const userAgent = req.headers['user-agent'] || 'unknown';
        const referer = req.headers['referer'] || '';
        
        console.log('=== 🔐 VERIFICATION ===');
        console.log('IP:', clientIP);
        console.log('Query Params:', req.query);

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

        // ✅ VERIFICAR SE JÁ EXISTE KEY ATIVA
        const existingKey = await getActiveKeyForIP(clientIP);
        if (existingKey) {
            console.log('ℹ️ Returning existing key for IP:', clientIP);
            
            // ✅ WEBHOOK PARA KEY EXISTENTE
            await sendWebhookLog({
                type: 'EXISTING_KEY_USED',
                ip: clientIP,
                key: existingKey.key,
                timestamp: new Date().toISOString()
            });
            
            return res.status(200).json({
                success: true,
                key: existingKey.key,
                expiresAt: existingKey.expiresAt,
                expiresIn: '24 hours',
                existing: true
            });
        }

        // ✅ GERAR NOVA KEY
        const keyData = generateSecureKey(clientIP, userAgent);
        console.log('✅ NEW KEY GENERATED:', keyData.key);

        // ✅ ENVIAR WEBHOOK DA NOVA KEY
        await sendWebhookLog({
            type: 'KEY_GENERATED',
            ip: clientIP,
            key: keyData.key,
            timestamp: new Date().toISOString(),
            userAgent: userAgent.substring(0, 100)
        });

        // ✅ ATUALIZAR ESTATÍSTICAS
        updateUserActivity(clientIP, keyData.key);

        res.setHeader('Content-Type', 'application/json');
        res.status(200).json({
            success: true,
            key: keyData.key,
            expiresAt: keyData.expiresAt,
            expiresIn: '24 hours',
            existing: false
        });

    } catch (error) {
        console.error('❌ Verify API error:', error);
        
        // ✅ WEBHOOK PARA ERRO
        await sendWebhookLog({
            type: 'SYSTEM_ERROR',
            ip: req.headers['x-forwarded-for'] || 'unknown',
            error: error.message,
            timestamp: new Date().toISOString()
        });
        
        res.status(500).json({ 
            success: false, 
            error: 'SYSTEM_ERROR',
            message: error.message 
        });
    }
}

// ✅ FUNÇÃO PARA ENVIAR WEBHOOK
async function sendWebhookLog(data) {
    try {
        let embed;

        if (data.type === 'KEY_GENERATED') {
            embed = {
                title: "🎉 **NOVA KEY GERADA** - MultiHub Key",
                color: 0x00ff00, // Verde
                description: "Uma nova key foi gerada com sucesso!",
                fields: [
                    {
                        name: "🔑 **Key**",
                        value: `\`\`\`${data.key}\`\`\``,
                        inline: false
                    },
                    {
                        name: "🌐 **IP**",
                        value: `\`${data.ip}\``,
                        inline: true
                    },
                    {
                        name: "⏰ **Expira em**",
                        value: "**24 horas** ⏳",
                        inline: true
                    },
                    {
                        name: "📅 **Data**",
                        value: `<t:${Math.floor(Date.now() / 1000)}:F>`,
                        inline: true
                    }
                ],
                timestamp: new Date().toISOString(),
                footer: {
                    text: "MultiHub Key System • LootLabs"
                },
                thumbnail: {
                    url: "https://cdn-icons-png.flaticon.com/512/1005/1005141.png"
                }
            };
        } 
        else if (data.type === 'EXISTING_KEY_USED') {
            embed = {
                title: "🔄 **KEY EXISTENTE REUTILIZADA**",
                color: 0xffa500, // Laranja
                description: "Usuário utilizou key existente ativa",
                fields: [
                    {
                        name: "🔑 **Key**",
                        value: `\`\`\`${data.key}\`\`\``,
                        inline: false
                    },
                    {
                        name: "🌐 **IP**",
                        value: `\`${data.ip}\``,
                        inline: true
                    },
                    {
                        name: "📅 **Data**",
                        value: `<t:${Math.floor(Date.now() / 1000)}:F>`,
                        inline: true
                    }
                ],
                timestamp: new Date().toISOString(),
                footer: {
                    text: "MultiHub Key System • Reutilização"
                }
            };
        }
        else if (data.type === 'FRAUD_BLOCKED') {
            embed = {
                title: "🚫 **TENTATIVA DE FRAUDE BLOQUEADA**",
                color: 0xff0000, // Vermelho
                description: "Sistema anti-fraude detectou atividade suspeita",
                fields: [
                    {
                        name: "🌐 **IP**",
                        value: `\`${data.ip}\``,
                        inline: true
                    },
                    {
                        name: "📛 **Razão**",
                        value: `**${data.reason}**`,
                        inline: true
                    },
                    {
                        name: "🛡️ **Ação**",
                        value: "**BLOQUEADO AUTOMATICAMENTE** 🔒",
                        inline: true
                    }
                ],
                timestamp: new Date().toISOString(),
                footer: {
                    text: "MultiHub Key System • Anti-Fraud"
                }
            };
        }
        else if (data.type === 'SYSTEM_ERROR') {
            embed = {
                title: "❌ **ERRO NO SISTEMA**",
                color: 0xff0000,
                fields: [
                    {
                        name: "💻 **Erro**",
                        value: `\`\`\`${data.error}\`\`\``,
                        inline: false
                    },
                    {
                        name: "🌐 **IP**",
                        value: `\`${data.ip}\``,
                        inline: true
                    }
                ],
                timestamp: new Date().toISOString(),
                footer: {
                    text: "MultiHub Key System • Error Log"
                }
            };
        }

        const response = await fetch(CONFIG.WEBHOOK_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                embeds: [embed],
                username: 'MultiHub Key Logger',
                avatar_url: 'https://cdn-icons-png.flaticon.com/512/1005/1005141.png'
            })
        });

        if (!response.ok) {
            console.log('❌ Webhook failed:', response.status);
        } else {
            console.log('✅ Webhook sent successfully');
        }
    } catch (error) {
        console.log('❌ Webhook error:', error.message);
    }
}

// ✅ FUNÇÃO PARA LOG DE FRAUDES
async function logFraudAttempt(ip, reason, queryParams) {
    console.log(`🚫 FRAUD: ${ip} - ${reason}`);
    
    // ✅ WEBHOOK PARA FRAUDE
    await sendWebhookLog({
        type: 'FRAUD_BLOCKED',
        ip: ip,
        reason: reason,
        timestamp: new Date().toISOString()
    });
    
    if (!fraudDetectionDB.has(ip)) {
        fraudDetectionDB.set(ip, { score: 1, lastAttempt: Date.now() });
    } else {
        const fraudData = fraudDetectionDB.get(ip);
        fraudData.score++;
        fraudData.lastAttempt = Date.now();
    }
}

// ... (MANTENHA AS OUTRAS FUNÇÕES COMO ESTAVAM)

async function getActiveKeyForIP(ip) {
    if (!userActivityDB.has(ip)) return null;
    
    const userData = userActivityDB.get(ip);
    const now = Date.now();
    
    for (const key of userData.keys) {
        if (verificationDB.has(key)) {
            const keyData = verificationDB.get(key);
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

async function performFraudCheck(ip, userAgent, referer, queryParams) {
    console.log('🔍 Performing fraud check...');
    
    const checks = {
        ipNotBanned: !fraudDetectionDB.has(ip) || fraudDetectionDB.get(ip).score < CONFIG.FRAUD_THRESHOLD,
        withinAttemptLimit: await checkAttemptLimit(ip),
        withinKeyLimit: await checkKeyLimit(ip),
        cooldownRespected: await checkCooldown(ip),
        validUserAgent: userAgent && userAgent.length > 5,
        validReferer: true,
        validParams: queryParams.verified === 'true' && queryParams.platform === 'lootlabs'
    };

    console.log('📊 Check results:', checks);

    const passedChecks = Object.values(checks).filter(Boolean).length;
    const totalChecks = Object.values(checks).length;
    
    if (passedChecks < 3) {
        return {
            allowed: false,
            reason: `Failed security checks (${passedChecks}/${totalChecks}) - Required: 3`
        };
    }

    return { allowed: true };
}

async function checkAttemptLimit(ip) {
    if (!userActivityDB.has(ip)) return true;
    const userData = userActivityDB.get(ip);
    const hourAgo = Date.now() - (60 * 60 * 1000);
    const recentAttempts = userData.attempts.filter(time => time > hourAgo);
    const result = recentAttempts.length < CONFIG.MAX_ATTEMPTS_PER_HOUR;
    console.log(`📈 Attempt check: ${recentAttempts.length}/${CONFIG.MAX_ATTEMPTS_PER_HOUR} - ${result}`);
    return result;
}

async function checkKeyLimit(ip) {
    if (!userActivityDB.has(ip)) return true;
    const userData = userActivityDB.get(ip);
    const activeKeys = userData.keys.filter(key => 
        verificationDB.has(key) && verificationDB.get(key).expiresAt > Date.now()
    );
    const result = activeKeys.length < CONFIG.MAX_KEYS_PER_IP;
    console.log(`🔑 Key limit check: ${activeKeys.length}/${CONFIG.MAX_KEYS_PER_IP} - ${result}`);
    return result;
}

async function checkCooldown(ip) {
    if (!userActivityDB.has(ip)) return true;
    const userData = userActivityDB.get(ip);
    
    if (userData.keys.length === 0) return true;
    
    const lastKeyTime = Math.max(...userData.keys.map(key => 
        verificationDB.has(key) ? verificationDB.get(key).createdAt : 0
    ));
    
    const cooldownTime = CONFIG.COOLDOWN_MINUTES * 60 * 1000;
    const timeSinceLastKey = Date.now() - lastKeyTime;
    const result = timeSinceLastKey > cooldownTime;
    
    console.log(`⏰ Cooldown check: ${Math.floor(timeSinceLastKey/1000)}s/${cooldownTime/1000}s - ${result}`);
    return result;
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
    userData.attempts.push(Date.now());
    
    if (userData.attempts.length > 50) {
        userData.attempts = userData.attempts.slice(-50);
    }
    if (userData.keys.length > 10) {
        userData.keys = userData.keys.slice(-10);
    }
}

// Export para outras APIs
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
    let expiredCount = 0;
    
    for (const [key, data] of verificationDB.entries()) {
        if (now > data.expiresAt) {
            verificationDB.delete(key);
            expiredCount++;
        }
    }
    
    if (expiredCount > 0) {
        console.log(`🧹 Cleaned up ${expiredCount} expired keys`);
    }
}, 60 * 60 * 1000);