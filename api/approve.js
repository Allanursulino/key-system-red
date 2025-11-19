import crypto from 'crypto';

const approvedCodes = new Map();

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'GET') {
    // ✅ GERAR CÓDIGO
    const approvalCode = crypto.randomBytes(8).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (30 * 60 * 1000);
    
    approvedCodes.set(approvalCode, {
      created: Date.now(),
      expires: expiresAt,
      used: false,
      ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });

    console.log('🆕 Approval code generated:', approvalCode);
    
    res.status(200).json({ 
      success: true, 
      approvalCode,
      expiresIn: '30 minutes',
      // ✅ LINK FIXO DO SEU LOOTLABS - SUBSTITUA PELO SEU!
      lootlabsUrl: 'https://lootdest.org/s?AL8n8hhY'
    });
  }
  
  else if (req.method === 'POST') {
    // ✅ VALIDAR CÓDIGO
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ success: false, error: 'Code required' });
    }
    
    if (approvedCodes.has(code) && !approvedCodes.get(code).used) {
      const codeData = approvedCodes.get(code);
      codeData.used = true;
      codeData.usedAt = Date.now();
      
      console.log('✅ Code validated:', code);
      
      res.status(200).json({ 
        success: true, 
        message: 'Code validated successfully'
      });
    } else {
      res.status(400).json({ success: false, error: 'Invalid or used code' });
    }
  }
}

export function validateApprovalCode(code) {
  if (!approvedCodes.has(code)) {
    return { valid: false, reason: 'Code not found' };
  }
  
  const codeData = approvedCodes.get(code);
  
  if (codeData.used) {
    return { valid: false, reason: 'Code already used' };
  }
  
  if (Date.now() > codeData.expires) {
    approvedCodes.delete(code);
    return { valid: false, reason: 'Code expired' };
  }
  
  return { valid: true, data: codeData };
}