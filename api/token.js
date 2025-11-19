import crypto from 'crypto';
import { getTokenStorage, cleanupTokens } from './_tokens.js';

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
      
      const tokens = getTokenStorage();
      tokens.set(token, {
        created: Date.now(),
        expires: expiresAt,
        used: false
      });

      console.log('🆕 Token generated:', token.substring(0, 12) + '...');
      console.log('📊 Total tokens:', tokens.size);
      
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