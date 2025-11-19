import crypto from 'crypto';

// Database em memória SEGURO
const verificationDB = new Map();
const userActivityDB = new Map();
const fraudDetectionDB = new Map();

// Configurações SEGURAS
const CONFIG = {
    MAX_KEYS_PER_IP: 1,
    KEY_EXPIRY_HOURS: 24,
    COOLDOWN_MINUTES: 5,
    MAX_ATTEMPTS_PER_HOUR: 10,
    FRAUD_THRESHOLD: 5
};

// Banco de dados de keys válidas (simula um banco real)
const validKeysDB = new Map();

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

        console.log('=== 🔐 VERIFICAÇÃO DE KEY ===');
        console.log('IP:', clientIP);
        console.log('Key:', key);

        // ✅ VERIFICAÇÃO DE SEGURANÇA
        const securityCheck = await performSecurityCheck(clientIP, key);
        
        if (!securityCheck.allowed) {
            console.log('🚫 BLOQUEADO:', securityCheck.reason);
            await logSecurityViolation(clientIP, securityCheck.reason, key);
            return res.status(403).json({
                success: false,
                message: securityCheck.reason
            });
        }

        // ✅ VALIDAÇÃO DA KEY
        const validationResult = await validateKeyInDatabase(key);
        
        if (!validationResult.valid) {
            console.log('❌ KEY INVÁLIDA:', validationResult.reason);
            return res.status(403).json({
                success: false,
                message: validationResult.reason
            });
        }

        console.log('✅ KEY VÁLIDA:', key);
        
        // ✅ RESPOSTA SEGURA
        res.status(200).json({
            success: true,
            message: 'Key válida',
            key: key,
            data: {
                expiresAt: validationResult.expiresAt,
                createdAt: validationResult.createdAt,
                uses: validationResult.uses
            }
        });

    } catch (error) {
        console.error('❌ Erro na API:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro interno do servidor' 
        });
    }
}

// ✅ VALIDAÇÃO SEGURA NO BANCO DE DADOS
async function validateKeyInDatabase(key) {
    // Verificar se a key existe no banco
    if (!validKeysDB.has(key)) {
        return { valid: false, reason: 'Key não encontrada no banco de dados' };
    }
    
    const keyData = validKeysDB.get(key);
    
    // Verificar se não expirou
    if (Date.now() > keyData.expiresAt) {
        validKeysDB.delete(key);
        return { valid: false, reason: 'Key expirada' };
    }
    
    // Verificar se não foi revogada
    if (!keyData.isValid) {
        return { valid: false, reason: 'Key revogada' };
    }
    
    // Atualizar contador de usos
    keyData.uses += 1;
    
    return {
        valid: true,
        expiresAt: keyData.expiresAt,
        createdAt: keyData.createdAt,
        uses: keyData.uses
    };
}

// ✅ VERIFICAÇÃO DE SEGURANÇA RIGOROSA
async function performSecurityCheck(ip, key) {
    // Verificar se a key foi fornecida
    if (!key || key === '') {
        return { allowed: false, reason: 'Key não fornecida' };
    }
    
    // Verificar formato da key (32 caracteres hex)
    if (!/^[A-F0-9]{32}$/.test(key)) {
        return { allowed: false, reason: 'Formato de key inválido' };
    }
    
    // Verificar limite de tentativas
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], validations: [] });
    }
    
    const userData = userActivityDB.get(ip);
    const hourAgo = Date.now() - (60 * 60 * 1000);
    const recentAttempts = userData.attempts.filter(time => time > hourAgo);
    
    if (recentAttempts.length >= CONFIG.MAX_ATTEMPTS_PER_HOUR) {
        return { allowed: false, reason: 'Muitas tentativas. Tente novamente em 1 hora.' };
    }
    
    // Registrar tentativa
    userData.attempts.push(Date.now());
    
    // Limitar histórico
    if (userData.attempts.length > 50) {
        userData.attempts = userData.attempts.slice(-50);
    }
    
    return { allowed: true };
}

// ✅ GERAR NOVA KEY (para a API de geração)
export function generateNewKey(ip, userAgent) {
    const key = crypto.randomBytes(16).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (CONFIG.KEY_EXPIRY_HOURS * 60 * 60 * 1000);
    
    // Salvar no banco de keys válidas
    validKeysDB.set(key, {
        ip: ip,
        userAgent: userAgent,
        createdAt: Date.now(),
        expiresAt: expiresAt,
        uses: 0,
        isValid: true
    });
    
    // Registrar no histórico do usuário
    if (!userActivityDB.has(ip)) {
        userActivityDB.set(ip, { attempts: [], validations: [], keys: [] });
    }
    userActivityDB.get(ip).keys.push(key);
    
    console.log('🔑 NOVA KEY GERADA:', key);
    
    return { key, expiresAt };
}

// ✅ VALIDAR KEY (para outras APIs)
export function validateKey(key) {
    return validateKeyInDatabase(key);
}

// ✅ LOG DE VIOLAÇÕES
async function logSecurityViolation(ip, reason, key) {
    console.log(`🚫 VIOLAÇÃO: ${ip} - ${reason} - Key: ${key}`);
    
    if (!fraudDetectionDB.has(ip)) {
        fraudDetectionDB.set(ip, { score: 1, lastViolation: Date.now() });
    } else {
        const fraudData = fraudDetectionDB.get(ip);
        fraudData.score += 1;
        fraudData.lastViolation = Date.now();
    }
}

// ✅ LIMPEZA AUTOMÁTICA
setInterval(() => {
    const now = Date.now();
    let expiredCount = 0;
    
    // Limpar keys expiradas
    for (const [key, data] of validKeysDB.entries()) {
        if (now > data.expiresAt) {
            validKeysDB.delete(key);
            expiredCount++;
        }
    }
    
    // Limpar histórico antigo
    for (const [ip, data] of userActivityDB.entries()) {
        const hourAgo = now - (60 * 60 * 1000);
        data.attempts = data.attempts.filter(time => time > hourAgo);
        data.validations = data.validations.filter(time => time > hourAgo);
        
        if (data.attempts.length === 0 && data.validations.length === 0 && data.keys.length === 0) {
            userActivityDB.delete(ip);
        }
    }
    
    if (expiredCount > 0) {
        console.log(`🧹 Limpas ${expiredCount} keys expiradas`);
    }
}, 30 * 60 * 1000); // A cada 30 minutos