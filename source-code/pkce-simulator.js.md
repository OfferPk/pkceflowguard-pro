/\*\*  
 \* PKCEFlowGuard Pro \- Threat & Interception Attack Simulator  
 \* Simulates Authorization Code Interception on mobile custom schemes and SPAs.  
 \* Demonstrates Scenario A (Vulnerable / Plain / No PKCE) vs Scenario B (Zero-Trust PKCE S256 Shield).  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.PKCESimulator \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const PKCESimulator \= {  
    /\*\*  
     \* Simulates Scenario A: Rogue App Interception without PKCE / with plain method  
     \*/  
    simulateScenarioA(params) {  
      const appName \= params.appName || 'Banking Mobile App';  
      const redirectScheme \= params.redirectScheme || 'myapp://oauth/callback';  
      const authCode \= params.authCode || 'auth\_code\_leaked\_98765';  
      const method \= params.method || 'plain';

      return {  
        scenario: 'SCENARIO\_A\_INTERCEPTION\_ATTACK',  
        title: 'Authorization Code Interception Attack (Vulnerable / Plain Mode)',  
        status: 'COMPROMISED',  
        severity: 'CRITICAL',  
        steps: \[  
          {  
            stepNumber: 1,  
            phase: 'User Authorization Request',  
            actor: 'Legitimate App',  
            description: \`Legitimate client launches browser with custom scheme \${redirectScheme}. \${method \=== 'plain' ? 'Sent code\_challenge\_method=plain (unhashed).' : 'No PKCE parameters attached.'}\`,  
            state: 'OUTBOUND\_DISPATCHED',  
            payload: \`GET /authorize?response\_type=code\&client\_id=client\_123\&redirect\_uri=\${encodeURIComponent(redirectScheme)}\${method \=== 'plain' ? '\&code\_challenge=MY\_SECRET\_VERIFIER\&code\_challenge\_method=plain' : ''}\`  
          },  
          {  
            stepNumber: 2,  
            phase: 'Authorization Server Callback',  
            actor: 'Identity Provider (IdP)',  
            description: 'User logs in; IdP dispatches callback URL with authorization code via operating system custom URI handler.',  
            state: 'REDIRECT\_BROADCAST',  
            payload: \`\${redirectScheme}?code=\${authCode}\&state=csrf\_test\_abc\`  
          },  
          {  
            stepNumber: 3,  
            phase: 'OS Intent / Scheme Interception',  
            actor: 'Malicious Rogue App (Attacker)',  
            description: 'Rogue application co-registered for the same custom URI scheme intercepts the redirect intent and extracts the raw authorization code.',  
            state: 'CODE\_STOLEN',  
            payload: \`INTERCEPTED\_CODE: \${authCode}\${method \=== 'plain' ? ' | STOLEN\_VERIFIER: MY\_SECRET\_VERIFIER' : ''}\`  
          },  
          {  
            stepNumber: 4,  
            phase: 'Attacker Token Request',  
            actor: 'Malicious Rogue App (Attacker)',  
            description: \`Attacker immediately posts stolen code to /token endpoint. \${method \=== 'plain' ? 'Supplies the intercepted plain verifier.' : 'No code\_verifier required by IdP.'}\`,  
            state: 'TOKEN\_DISPATCH',  
            payload: \`POST /token\\ngrant\_type=authorization\_code\\ncode=\${authCode}\\nclient\_id=client\_123\${method \=== 'plain' ? '\\ncode\_verifier=MY\_SECRET\_VERIFIER' : ''}\`  
          },  
          {  
            stepNumber: 5,  
            phase: 'Cryptographic Validation & Token Release',  
            actor: 'Identity Provider (IdP)',  
            description: 'IdP cannot verify caller authenticity. Tokens issued directly to the attacker.',  
            state: 'BREACH\_CONFIRMED',  
            payload: 'HTTP 200 OK\\n{\\n  "access\_token": "eyJhbGciOi...",\\n  "refresh\_token": "rfr\_malicious\_takeover\_999",\\n  "expires\_in": 3600\\n}'  
          }  
        \],  
        impact: 'Full account takeover. Attacker obtains valid OAuth tokens and exfiltrates financial/customer data with zero client authentication.'  
      };  
    },

    /\*\*  
     \* Simulates Scenario B: Zero-Trust PKCE S256 Cryptographic Shield  
     \*/  
    simulateScenarioB(params) {  
      const appName \= params.appName || 'Banking Mobile App';  
      const redirectScheme \= params.redirectScheme || 'myapp://oauth/callback';  
      const authCode \= params.authCode || 'auth\_code\_secure\_43210';  
      const verifier \= params.verifier || 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6';  
      const challenge \= params.challenge || 'CHALLENGE\_S256\_HASH\_XYZ';

      return {  
        scenario: 'SCENARIO\_B\_PKCE\_SHIELD',  
        title: 'Zero-Trust PKCE S256 Cryptographic Shield (Hardened)',  
        status: 'PROTECTED',  
        severity: 'SECURE',  
        steps: \[  
          {  
            stepNumber: 1,  
            phase: 'Client Secret Generation',  
            actor: 'Legitimate App',  
            description: 'Client generates high-entropy code\_verifier in volatile memory and calculates SHA-256 code\_challenge.',  
            state: 'SECRET\_BOUND\_LOCALLY',  
            payload: \`code\_verifier: \${verifier.substring(0, 16)}... (isolated in memory)\\ncode\_challenge: \${challenge}\\ncode\_challenge\_method: S256\`  
          },  
          {  
            stepNumber: 2,  
            phase: 'Authorization Request with Challenge',  
            actor: 'Legitimate App',  
            description: 'Client dispatches authorization request containing only the derived one-way SHA-256 challenge.',  
            state: 'CHALLENGE\_REGISTERED',  
            payload: \`GET /authorize?response\_type=code\&client\_id=client\_123\&redirect\_uri=\${encodeURIComponent(redirectScheme)}\&code\_challenge=\${challenge}\&code\_challenge\_method=S256\`  
          },  
          {  
            stepNumber: 3,  
            phase: 'Authorization Code Interception Attempt',  
            actor: 'Malicious Rogue App (Attacker)',  
            description: 'Rogue app intercepts the custom URI redirect and extracts authorization code. However, it CANNOT extract the memory-isolated code\_verifier.',  
            state: 'CODE\_STOLEN\_BUT\_USELESS',  
            payload: \`STOLEN\_CODE: \${authCode}\\nMISSING: code\_verifier (Held only in legitimate app memory)\`  
          },  
          {  
            stepNumber: 4,  
            phase: 'Attacker Token Request Attempt',  
            actor: 'Malicious Rogue App (Attacker)',  
            description: 'Attacker attempts token exchange with stolen code, but lacks the secret verifier (submits dummy string or empty value).',  
            state: 'ATTACK\_ATTEMPTED',  
            payload: \`POST /token\\ngrant\_type=authorization\_code\\ncode=\${authCode}\\nclient\_id=client\_123\\ncode\_verifier=attacker\_guessed\_string\_999\`  
          },  
          {  
            stepNumber: 5,  
            phase: 'IdP SHA-256 Verification & Defense Gate',  
            actor: 'Identity Provider (IdP)',  
            description: 'IdP re-calculates Base64URL(SHA256(code\_verifier)). Hash mismatch\! Token request is terminated instantly.',  
            state: 'ATTACK\_NEUTRALIZED',  
            payload: 'HTTP 400 Bad Request\\n{\\n  "error": "invalid\_grant",\\n  "error\_description": "PKCE verification failed. Code verifier does not match registered code challenge."\\n}'  
          },  
          {  
            stepNumber: 6,  
            phase: 'Legitimate Client Token Exchange',  
            actor: 'Legitimate App',  
            description: 'Legitimate client sends POST /token with real in-memory code\_verifier. Server verifies hash and issues tokens safely.',  
            state: 'AUTHENTICATED\_SAFELY',  
            payload: 'HTTP 200 OK (Tokens granted exclusively to legitimate app)'  
          }  
        \],  
        impact: 'Cryptographically guaranteed protection. Intercepted authorization codes are rendered completely useless without the ephemeral pre-image code\_verifier.'  
      };  
    }  
  };

  return PKCESimulator;  
});  
