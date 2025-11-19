import crypto from 'crypto';

// Armazenar tokens válidos
const validTokens = new Map();

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'GET') {
    try {
      // Gerar token único
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + (30 * 60 * 1000); // 30 minutos
      
      validTokens.set(token, {
        created: Date.now(),
        expires: expiresAt,
        used: false
      });

      console.log('🆕 Token generated:', token.substring(0, 12) + '...');
      
      // Limpar tokens expirados
      cleanupTokens();
      
      res.status(200).json({ 
        success: true, 
        token,
        expires: expiresAt,
        message: 'Token valid for 30 minutes'
      });
      
    } catch (error) {
      console.error('❌ Token generation error:', error);
      res.status(500).json({ success: false, error: 'Failed to generate token' });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}

// Verificar se token é válido (usado pelo generate.js)
export function validateToken(token) {
  if (!validTokens.has(token)) {
    return { valid: false, reason: 'Token not found' };
  }
  
  const tokenData = validTokens.get(token);
  
  if (tokenData.used) {
    return { valid: false, reason: 'Token already used' };
  }
  
  if (Date.now() > tokenData.expires) {
    validTokens.delete(token);
    return { valid: false, reason: 'Token expired' };
  }
  
  // Marcar como usado
  tokenData.used = true;
  tokenData.usedAt = Date.now();
  
  return { valid: true, data: tokenData };
}

// Limpar tokens expirados
function cleanupTokens() {
  const now = Date.now();
  for (const [token, data] of validTokens.entries()) {
    if (now > data.expires) {
      validTokens.delete(token);
    }
  }
}