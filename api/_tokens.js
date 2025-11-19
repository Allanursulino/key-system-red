// api/_tokens.js - Storage compartilhado entre APIs
const validTokens = new Map();

export function getTokenStorage() {
  return validTokens;
}

export function validateToken(token) {
  const tokens = getTokenStorage();
  
  console.log('🔐 Validating token:', token ? token.substring(0, 12) + '...' : 'NULL');
  console.log('📊 Tokens in storage:', tokens.size);
  
  if (!tokens.has(token)) {
    console.log('❌ Token not found in storage');
    return { valid: false, reason: 'Token not found' };
  }
  
  const tokenData = tokens.get(token);
  
  if (tokenData.used) {
    console.log('❌ Token already used');
    return { valid: false, reason: 'Token already used' };
  }
  
  if (Date.now() > tokenData.expires) {
    tokens.delete(token);
    console.log('❌ Token expired');
    return { valid: false, reason: 'Token expired' };
  }
  
  // Marcar como usado
  tokenData.used = true;
  tokenData.usedAt = Date.now();
  
  console.log('✅ Token valid');
  return { valid: true, data: tokenData };
}

export function cleanupTokens() {
  const tokens = getTokenStorage();
  const now = Date.now();
  let cleaned = 0;
  
  for (const [token, data] of tokens.entries()) {
    if (now > data.expires) {
      tokens.delete(token);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned ${cleaned} expired tokens`);
  }
}