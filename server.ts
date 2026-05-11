/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import cors from 'cors';
import * as dns from 'node:dns/promises';
import * as tls from 'node:tls';
import whois from 'whois-json';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { createServer as createViteServer } from 'vite';
import 'dotenv/config';
import { GoogleGenerativeAI } from '@google/generative-ai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('INIT: Phish Intel Intelligence Node starting...');

const apiKey = process.env.GEMINI_API_KEY;

// Helper functions moved to module level
async function getSSLInfo(hostname: string) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
    }, () => {
      if (resolved) return;
      resolved = true;
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError;
      socket.end();
      if (!cert || Object.keys(cert).length === 0) {
        resolve({ error: 'No certificate returned' });
      } else {
        resolve({
          authorized,
          authorizationError,
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          fingerprint: cert.fingerprint,
          serialNumber: cert.serialNumber,
          bits: cert.bits,
          hasSCT: !!(cert as any).sctList || !!(cert as any).raw?.toString('hex').includes('13614111129242')
        });
      }
    });

    socket.on('error', (e: any) => {
      if (resolved) return;
      resolved = true;
      resolve({ error: e.message || 'SSL Error', code: e.code });
    });

    socket.setTimeout(5000, () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({ error: 'SSL Timeout', code: 'ETIMEDOUT' });
    });
  });
}

function calculateEntropy(str: string) {
  const len = str.length;
  const frequencies = new Map();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isSuspiciousTLD(hostname: string) {
  const tld = hostname.split('.').pop()?.toLowerCase();
  const highRiskTLDs = ['top', 'xyz', 'icu', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'win', 'bid', 'click', 'accountant', 'download', 'review', 'faith', 'science', 'party', 'cricket', 'reisen', 'casa', 'monster', 'online', 'vip', 'quest', 'tokyo'];
  return highRiskTLDs.includes(tld || '');
}

function isURLShortener(hostname: string) {
  const shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 'bl.ink'];
  return shorteners.includes(hostname.toLowerCase());
}

async function startServer() {
  const app = express();
  app.use(cors());
  app.use(express.json());

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), ai: !!process.env.GEMINI_API_KEY });
  });

  // Intel route
  app.post('/api/analyze', async (req, res) => {
    const { url: target } = req.body;
    if (!target) return res.status(400).json({ error: 'Target required' });

    console.log(`ANALYSIS_REQUEST: ${target}`);

    let type: any = 'domain';
    let hostname = '';
    
    // Quick classification
    if (target.includes('@')) {
      type = 'email';
      hostname = target.split('@')[1];
    } else if (/^\+?[\d\s-]{7,15}$/.test(target)) {
      type = 'phone';
      hostname = target;
    } else if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) {
      type = 'ip';
      hostname = target;
    } else if (target.split(' ').length > 2 || (target.length > 30 && target.includes(' '))) {
      type = 'message';
      hostname = 'N/A';
    } else {
      try {
        const isDeepLink = /^[a-z][a-z0-9+.-]*:/i.test(target) && !target.startsWith('http');
        
        if (isDeepLink) {
          type = 'url';
          try {
            const urlObj = new URL(target);
            hostname = urlObj.hostname || 'N/A';
          } catch {
            hostname = 'N/A';
          }
        } else {
          const urlObj = new URL(target.startsWith('http') ? target : `https://${target}`);
          hostname = urlObj.hostname;
          type = target.startsWith('http') ? 'url' : 'domain';
        }
      } catch (e) {
        hostname = target;
        type = 'domain';
      }
    }

    try {
      // Intel gathering
      let dnsInfo: any = { ips: [], records: {}, reputation: [], vulnerabilities: [] };
      if (type === 'ip') {
        dnsInfo.ips = [hostname];
      } else if (!['phone', 'keyword', 'message'].includes(type)) {
        try {
          dnsInfo.ips = await dns.resolve4(hostname).catch(() => []);
          dnsInfo.records.mx = await dns.resolveMx(hostname).catch(() => []);
          dnsInfo.records.txt = await dns.resolveTxt(hostname).catch(() => []);
        } catch (e) {}
      }

      let sslInfo: any = null;
      let whoisInfo: any = null;
      if (!['ip', 'phone', 'message'].includes(type) && hostname !== 'N/A') {
        sslInfo = await getSSLInfo(hostname);
        try { whoisInfo = await whois(hostname); } catch (e) {}
      }

      const heuristics = {
        isPunycode: hostname.startsWith('xn--'),
        entropy: calculateEntropy(target),
        suspiciousTLD: isSuspiciousTLD(hostname),
        isShortener: isURLShortener(hostname)
      };

      // AI Analysis
      let aiData: any = null;
      try {
        if (!apiKey || apiKey === 'YOUR_API_KEY_HERE') {
          throw new Error('GEMINI_API_KEY_MISSING');
        }
        
        const client = new GoogleGenerativeAI(apiKey);
        const model = client.getGenerativeModel({ model: "gemini-1.5-flash" });
        const prompt = `Perform security threat analysis on ${type}: ${target}. Technical data: DNS=${JSON.stringify(dnsInfo)}, SSL=${JSON.stringify(sslInfo)}, WHOIS=${JSON.stringify(whoisInfo)}, Heuristics=${JSON.stringify(heuristics)}. Return JSON: {threatScore: 0-100, classification: "Safe"|"Suspicious"|"Phishing"|"Malicious", explanation: "...", recommendation: "...", riskIndicators: [], technicalSummary: {}}`;
        const result = await model.generateContent(prompt);
        const text = result.response.text();
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        aiData = jsonMatch ? JSON.parse(jsonMatch[0]) : null;
      } catch (e: any) {
        let errorMsg = 'AI analysis unavailable.';
        const errStr = String(e);
        
        if (errStr.includes('GEMINI_API_KEY_MISSING')) {
          errorMsg = 'AI intelligence bypass active: GEMINI_API_KEY not found in system environment. Please configure it in the Settings menu.';
        } else if (errStr.includes('API key not valid')) {
          errorMsg = 'AI handshake failed: The provided GEMINI_API_KEY is rejected by Google Cloud. Verify your API key in the Settings menu.';
        } else if (errStr.includes('Quota exceeded')) {
          errorMsg = 'AI resource exhausted: API rate limit reached. Please try again later.';
        } else {
          errorMsg = `AI process fault: ${e.message || 'Unknown internal error'}`;
        }
        
        console.error('AI analysis skipped/failed:', e.message);
        aiData = {
          threatScore: heuristics.suspiciousTLD ? 50 : 10,
          classification: heuristics.suspiciousTLD ? 'Suspicious' : 'Safe',
          explanation: `Heuristic fallback activated. ${errorMsg}`,
          recommendation: 'Check technical markers manually.',
          riskIndicators: [],
          technicalSummary: {}
        };
      }

      res.json({
        ...aiData,
        type,
        target,
        raw: { dns: dnsInfo, ssl: sslInfo || {}, whois: whoisInfo || {}, heuristics }
      });
    } catch (err) {
      console.error('Pipeline error:', err);
      res.status(500).json({ error: 'Pipeline failure' });
    }
  });

  // Vite or Static
  if (process.env.NODE_ENV !== 'production') {
    try {
      console.log('BOOT: Starting Vite middleware...');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      console.log('BOOT: Vite middleware initialized.');
      app.use(vite.middlewares);
    } catch (viteErr) {
      console.error('ERROR: Failed to initialize Vite middleware:', viteErr);
      app.get('*', (req, res) => {
        res.status(503).send('Vite is starting up or failed to start. Please refresh in a moment.');
      });
    }
  } else {
    const staticPath = path.join(__dirname, 'dist');
    app.use(express.static(staticPath));
    app.get('*', (req, res) => res.sendFile(path.join(staticPath, 'index.html')));
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`READY: Phish Intel Node alive on port ${PORT}`);
  });
}

startServer().catch(err => {
  console.error('FATAL: Startup failure', err);
  process.exit(1);
});
