/\*\*  
 \* PKCEFlowGuard Pro \- 10-Point Zero-Trust OAuth 2.1 / PKCE Security Auditor  
 \* Audits PKCE configurations against RFC 7636, OAuth 2.1 draft, and OWASP Top 10 API Security.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    const PKCEEngine \= require('./pkce-engine.js');  
    module.exports \= factory(PKCEEngine);  
  } else {  
    root.PKCEAuditor \= factory(root.PKCEEngine);  
  }  
})(typeof self \!== 'undefined' ? self : this, function (PKCEEngine) {  
  'use strict';

  const PKCEAuditor \= {  
    /\*\*  
     \* Runs a comprehensive 10-point Zero-Trust audit on the provided PKCE configuration  
     \* @param {Object} config  
     \* @returns {Object} audit report with score, grade, checks array, and remediation guidance  
     \*/  
    audit(config) {  
      const verifier \= config.codeVerifier || '';  
      const challenge \= config.codeChallenge || '';  
      const method \= config.codeChallengeMethod || 'S256';  
      const authEndpoint \= config.authEndpoint || '';  
      const redirectUri \= config.redirectUri || '';  
      const clientId \= config.clientId || '';  
      const state \= config.state || '';  
      const storageType \= config.storageType || 'memory'; // 'memory', 'sessionStorage', 'localStorage', 'cookie'

      const checks \= \[\];  
      let totalScore \= 0;

      // 1\. Challenge Method Enforcement (15 pts)  
      if (method \=== 'S256') {  
        checks.push({  
          id: 'method\_s256',  
          title: 'Challenge Method Enforcement',  
          points: 15,  
          maxPoints: 15,  
          passed: true,  
          level: 'PASS',  
          message: 'RFC 7636 mandatory SHA-256 method (S256) is enforced.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 15;  
      } else if (method \=== 'plain') {  
        checks.push({  
          id: 'method\_s256',  
          title: 'Challenge Method Enforcement',  
          points: 0,  
          maxPoints: 15,  
          passed: false,  
          level: 'CRITICAL',  
          message: 'CRITICAL VULNERABILITY: code\_challenge\_method=plain is active\! Plain text verifiers leak over authorization requests and allow trivial code interception.',  
          remediation: 'Immediately enforce code\_challenge\_method=S256 across all client applications and disable plain method support on your Authorization Server.'  
        });  
      } else {  
        checks.push({  
          id: 'method\_s256',  
          title: 'Challenge Method Enforcement',  
          points: 0,  
          maxPoints: 15,  
          passed: false,  
          level: 'CRITICAL',  
          message: \`Unknown code\_challenge\_method: "\${method}". Only S256 is permitted under OAuth 2.1.\`,  
          remediation: 'Configure code\_challenge\_method=S256.'  
        });  
      }

      // 2\. Verifier Length Bounds (10 pts)  
      const len \= verifier.length;  
      if (len \>= 43 && len \<= 128\) {  
        checks.push({  
          id: 'verifier\_length',  
          title: 'Code Verifier Length Bounds',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: \`Verifier length (\${len} chars) satisfies RFC 7636 bounds (43 ≤ length ≤ 128).\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'verifier\_length',  
          title: 'Code Verifier Length Bounds',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Verifier length (\${len} chars) violates RFC 7636 Section 4.1 requirements (minimum 43, maximum 128).\`,  
          remediation: 'Generate code\_verifier with at least 43 and at most 128 characters. Recommended length is 64–128 characters.'  
        });  
      }

      // 3\. Cryptographic Entropy (10 pts)  
      const entropy \= PKCEEngine.calculateEntropy(verifier);  
      if (entropy.totalBits \>= 256\) {  
        checks.push({  
          id: 'crypto\_entropy',  
          title: 'Cryptographic Entropy',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: \`High cryptographic entropy detected (\${entropy.totalBits} total bits, \${entropy.shannonEntropy} bits/char). Exceeds 256-bit requirement.\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else if (entropy.totalBits \>= 150\) {  
        checks.push({  
          id: 'crypto\_entropy',  
          title: 'Cryptographic Entropy',  
          points: 5,  
          maxPoints: 10,  
          passed: false,  
          level: 'WARN',  
          message: \`Moderate entropy (\${entropy.totalBits} bits). RFC 7636 recommends at least 256 bits of entropy.\`,  
          remediation: 'Use crypto.getRandomValues() with a 64+ character unreserved charset to reach ≥ 256 bits of entropy.'  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'crypto\_entropy',  
          title: 'Cryptographic Entropy',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Inadequate entropy (\${entropy.totalBits} bits). Predictable or low-entropy verifiers can be brute-forced.\`,  
          remediation: 'Replace custom random logic with CSPRNG (crypto.getRandomValues or crypto.randomBytes).'  
        });  
      }

      // 4\. Base64URL Format Compliance (10 pts)  
      const hasPadding \= challenge.includes('=');  
      const hasIllegalChars \= challenge.includes('+') || challenge.includes('/');  
      if (challenge && \!hasPadding && \!hasIllegalChars) {  
        checks.push({  
          id: 'base64url\_compliance',  
          title: 'Base64URL Format Compliance',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Code challenge adheres to RFC 4648 Base64URL format without padding (=) or illegal URL characters (+, /).',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'base64url\_compliance',  
          title: 'Base64URL Format Compliance',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Invalid Base64URL encoding: \${hasPadding ? 'contains forbidden padding "="; ' : ''}\${hasIllegalChars ? 'contains standard Base64 characters "+", "/";' : ''}\`,  
          remediation: 'Transform Base64 to Base64URL: replace "+" with "-", "/" with "\_", and strip trailing "=" padding.'  
        });  
      }

      // 5\. Verifier Character Set Whitelist (10 pts)  
      const charsetCheck \= PKCEEngine.validateVerifierCharset(verifier);  
      if (charsetCheck.valid && verifier.length \> 0\) {  
        checks.push({  
          id: 'charset\_whitelist',  
          title: 'Verifier Character Set Whitelist',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'All verifier characters belong strictly to RFC 7636 unreserved set \[A-Za-z0-9-.\_\~\].',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'charset\_whitelist',  
          title: 'Verifier Character Set Whitelist',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Illegal characters found in verifier: \${charsetCheck.invalidChars.join(', ')}. RFC 7636 only permits \[A-Za-z0-9-.\_\~\].\`,  
          remediation: 'Sanitize verifier generation to strictly sample from the 66 RFC 7636 unreserved characters.'  
        });  
      }

      // 6\. CSRF State Parameter Protection (10 pts)  
      if (state && state.length \>= 16\) {  
        checks.push({  
          id: 'state\_parameter',  
          title: 'CSRF State Parameter Protection',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: \`State parameter is present with high entropy (\${state.length} chars) protecting against Cross-Site Request Forgery.\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else if (state && state.length \> 0\) {  
        checks.push({  
          id: 'state\_parameter',  
          title: 'CSRF State Parameter Protection',  
          points: 5,  
          maxPoints: 10,  
          passed: false,  
          level: 'WARN',  
          message: \`State parameter is short (\${state.length} chars). High-entropy state (≥ 16 chars) is strongly recommended.\`,  
          remediation: 'Generate state parameter with at least 16 cryptographically random characters.'  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'state\_parameter',  
          title: 'CSRF State Parameter Protection',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: 'Missing "state" parameter\! Authorization flow is vulnerable to login CSRF and session fixation attacks.',  
          remediation: 'Generate and validate an unguessable state parameter tied to the user session.'  
        });  
      }

      // 7\. Authorization URL Parameter Structure (10 pts)  
      const hasAuthEndpoint \= Boolean(authEndpoint && authEndpoint.startsWith('https\://'));  
      const hasClientId \= Boolean(clientId && clientId.length \> 0);  
      if (hasAuthEndpoint && hasClientId) {  
        checks.push({  
          id: 'auth\_url\_structure',  
          title: 'Authorization URL Structure',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Authorization endpoint uses TLS (HTTPS) and client\_id parameter is populated.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'auth\_url\_structure',  
          title: 'Authorization URL Structure',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Insecure or incomplete authorization endpoint: \${\!hasAuthEndpoint ? 'must use https\://;' : ''} \${\!hasClientId ? 'client\_id is required;' : ''}\`,  
          remediation: 'Ensure authEndpoint is an HTTPS URL and provide a valid registered client\_id.'  
        });  
      }

      // 8\. Token Exchange Payload Integrity (10 pts)  
      const derivedChallenge \= PKCEEngine.deriveCodeChallenge(verifier, method);  
      const challengeMatches \= derivedChallenge \=== challenge;  
      if (challengeMatches) {  
        checks.push({  
          id: 'token\_exchange\_match',  
          title: 'Token Exchange Payload Integrity',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Verifier and challenge cryptographically match. Token endpoint exchange will succeed.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'token\_exchange\_match',  
          title: 'Token Exchange Payload Integrity',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'CRITICAL',  
          message: 'Cryptographic mismatch\! The provided code\_verifier does not produce the specified code\_challenge. Authorization server will reject token exchange with HTTP 400 invalid\_grant.',  
          remediation: 'Ensure the client passes the exact original code\_verifier generated before the authorization request.'  
        });  
      }

      // 9\. Redirect URI Scheme Security (10 pts)  
      const isHttps \= redirectUri.startsWith('https\://');  
      const isLocalhost \= redirectUri.startsWith('http\://localhost') || redirectUri.startsWith('http\://127.0.0.1');  
      const isCustomScheme \= /^\[a-zA-Z\]\[a-zA-Z0-9+.-\]\*:\\/\\//.test(redirectUri) && \!redirectUri.startsWith('http\://');

      if (isHttps || isLocalhost || isCustomScheme) {  
        checks.push({  
          id: 'redirect\_uri\_security',  
          title: 'Redirect URI Scheme Security',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: \`Redirect URI uses secure scheme: \${isHttps ? 'HTTPS' : isLocalhost ? 'Localhost development' : 'Mobile Custom/Universal Scheme'}.\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'redirect\_uri\_security',  
          title: 'Redirect URI Scheme Security',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Insecure HTTP redirect URI: "\${redirectUri}". OAuth 2.1 strictly forbids unencrypted HTTP redirects outside of localhost.\`,  
          remediation: 'Use https\:// for web apps or claimed App Links / Universal Links for mobile applications.'  
        });  
      }

      // 10\. Storage & Ephemeral Lifecycle (5 pts)  
      if (storageType \=== 'memory' || storageType \=== 'sessionStorage') {  
        checks.push({  
          id: 'storage\_security',  
          title: 'Storage & Ephemeral Lifecycle',  
          points: 5,  
          maxPoints: 5,  
          passed: true,  
          level: 'PASS',  
          message: \`Ephemeral storage selected (\${storageType}). Verifier is isolated from persistent disk access.\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'storage\_security',  
          title: 'Storage & Ephemeral Lifecycle',  
          points: 0,  
          maxPoints: 5,  
          passed: false,  
          level: 'WARN',  
          message: \`Insecure persistent storage (\${storageType}). Storing PKCE verifiers in persistent localStorage leaves them vulnerable to XSS extraction.\`,  
          remediation: 'Keep code\_verifier in memory or short-lived sessionStorage cleared immediately after token exchange.'  
        });  
      }

      // Grade Calculation  
      let grade \= 'F';  
      if (totalScore \>= 95\) grade \= 'A+';  
      else if (totalScore \>= 90\) grade \= 'A';  
      else if (totalScore \>= 80\) grade \= 'B';  
      else if (totalScore \>= 70\) grade \= 'C';  
      else grade \= 'F';

      return {  
        score: totalScore,  
        maxScore: 100,  
        grade,  
        isProductionReady: totalScore \>= 90 && method \=== 'S256',  
        checks,  
        summary: \`PKCE Security Audit: \${totalScore}/100 (Grade \${grade}) \- \${totalScore \>= 90 ? 'Production Ready' : 'Remediation Required'}\`  
      };  
    }  
  };

  return PKCEAuditor;  
});  
