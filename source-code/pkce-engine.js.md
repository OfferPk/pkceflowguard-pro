/\*\*  
 \* PKCEFlowGuard Pro \- RFC 7636 Core PKCE Engine  
 \* Handles cryptographic code verifier generation, SHA-256 code challenge derivation,  
 \* Base64URL encoding, entropy calculations, and OAuth 2.1 URL synthesis.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.PKCEEngine \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  // RFC 7636 Section 4.1: unreserved characters \= ALPHA / DIGIT / "-" / "." / "\_" / "\~"  
  const UNRESERVED\_CHARSET \= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.\_\~';

  /\*\*  
   \* Pure JS SHA-256 Implementation for synchronous environments / Node / Fallback  
   \*/  
  function sha256Sync(asciiStr) {  
    function rightRotate(value, amount) {  
      return (value \>\>\> amount) | (value \<\< (32 \- amount));  
    }

    const mathPow \= Math.pow;  
    const maxWord \= mathPow(2, 32);  
    let i, j;  
    let result \= '';

    const words \= \[\];  
    const asciiBitLength \= asciiStr.length \* 8;

    let hash \= \[\];  
    let k \= \[\];  
    let primeCounter \= 0;

    const isPrime \= {};  
    for (let candidate \= 2; primeCounter \< 64; candidate++) {  
      if (\!isPrime\[candidate\]) {  
        for (i \= 0; i \< 313; i \+= candidate) {  
          isPrime\[i\] \= candidate;  
        }  
        hash\[primeCounter\] \= (mathPow(candidate, 0.5) \* maxWord) | 0;  
        k\[primeCounter++\] \= (mathPow(candidate, 1 / 3\) \* maxWord) | 0;  
      }  
    }

    asciiStr \+= '\\x80';  
    while ((asciiStr.length % 64\) \- 56\) asciiStr \+= '\\x00';  
    for (i \= 0; i \< asciiStr.length; i++) {  
      j \= asciiStr.charCodeAt(i);  
      if (j \>\> 8\) return; // RFC 7636 code\_verifier must be ASCII  
      words\[i \>\> 2\] |= j \<\< (((3 \- i) % 4\) \* 8);  
    }  
    words\[words.length\] \= (asciiBitLength / maxWord) | 0;  
    words\[words.length\] \= asciiBitLength | 0;

    for (j \= 0; j \< words.length; ) {  
      const w \= words.slice(j, (j \+= 16));  
      const oldHash \= hash;  
      hash \= hash.slice(0, 8);

      for (i \= 0; i \< 64; i++) {  
        const i2 \= i \+ j;  
        const w15 \= w\[i \- 15\],  
          w2 \= w\[i \- 2\];

        const s0 \= rightRotate(w15, 7\) ^ rightRotate(w15, 18\) ^ (w15 \>\>\> 3);  
        const s1 \= rightRotate(w2, 17\) ^ rightRotate(w2, 19\) ^ (w2 \>\>\> 10);  
        w\[i\] \=  
          i \< 16  
            ? w\[i\]  
            : (w\[i \- 16\] \+ s0 \+ w\[i \- 7\] \+ s1) | 0;

        const s1Round \=  
          rightRotate(hash\[4\], 6\) ^ rightRotate(hash\[4\], 11\) ^ rightRotate(hash\[4\], 25);  
        const ch \= (hash\[4\] & hash\[5\]) ^ (\~hash\[4\] & hash\[6\]);  
        const temp1 \= (hash\[7\] \+ s1Round \+ ch \+ k\[i\] \+ w\[i\]) | 0;  
        const s0Round \=  
          rightRotate(hash\[0\], 2\) ^ rightRotate(hash\[0\], 13\) ^ rightRotate(hash\[0\], 22);  
        const maj \= (hash\[0\] & hash\[1\]) ^ (hash\[0\] & hash\[2\]) ^ (hash\[1\] & hash\[2\]);  
        const temp2 \= (s0Round \+ maj) | 0;

        hash \= \[(temp1 \+ temp2) | 0\].concat(hash);  
        hash\[4\] \= (hash\[4\] \+ temp1) | 0;  
      }

      for (i \= 0; i \< 8; i++) {  
        hash\[i\] \= (hash\[i\] \+ oldHash\[i\]) | 0;  
      }  
    }

    const bytes \= \[\];  
    for (i \= 0; i \< 8; i++) {  
      for (j \= 3; j \>= 0; j--) {  
        bytes.push((hash\[i\] \>\> (8 \* j)) & 255);  
      }  
    }  
    return new Uint8Array(bytes);  
  }

  /\*\*  
   \* Base64URL Encoding without padding (RFC 7636 Section 3 & RFC 4648\)  
   \*/  
  function base64UrlEncode(bytes) {  
    let binary \= '';  
    const len \= bytes.byteLength;  
    for (let i \= 0; i \< len; i++) {  
      binary \+= String.fromCharCode(bytes\[i\]);  
    }  
    let base64 \= '';  
    if (typeof btoa \=== 'function') {  
      base64 \= btoa(binary);  
    } else if (typeof Buffer \!== 'undefined') {  
      base64 \= Buffer.from(binary, 'binary').toString('base64');  
    } else {  
      // Fallback btoa  
      const chars \= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';  
      for (let i \= 0; i \< binary.length; i \+= 3\) {  
        const b1 \= binary.charCodeAt(i);  
        const b2 \= binary.charCodeAt(i \+ 1);  
        const b3 \= binary.charCodeAt(i \+ 2);  
        base64 \+= chars.charAt(b1 \>\> 2);  
        base64 \+= chars.charAt(((b1 & 3\) \<\< 4\) | (b2 \>\> 4));  
        base64 \+= isNaN(b2) ? '=' : chars.charAt(((b2 & 15\) \<\< 2\) | (b3 \>\> 6));  
        base64 \+= isNaN(b3) ? '=' : chars.charAt(b3 & 63);  
      }  
    }  
    return base64  
      .replace(/\\+/g, '-')  
      .replace(/\\//g, '\_')  
      .replace(/=/g, '');  
  }

  const PKCEEngine \= {  
    UNRESERVED\_CHARSET,

    /\*\*  
     \* Generates a cryptographically strong code verifier (RFC 7636 Sec 4.1)  
     \* Length between 43 and 128 characters.  
     \*/  
    generateCodeVerifier(length \= 64\) {  
      const len \= Math.max(43, Math.min(128, length));  
      let verifier \= '';  
      const charsetLen \= UNRESERVED\_CHARSET.length;

      if (typeof crypto \!== 'undefined' && crypto.getRandomValues) {  
        const randomValues \= new Uint8Array(len);  
        crypto.getRandomValues(randomValues);  
        for (let i \= 0; i \< len; i++) {  
          verifier \+= UNRESERVED\_CHARSET\[randomValues\[i\] % charsetLen\];  
        }  
      } else {  
        // Fallback for Node.js / non-browser test environment  
        let cryptoMod \= null;  
        try {  
          cryptoMod \= require('crypto');  
        } catch (e) {}

        if (cryptoMod && cryptoMod.randomBytes) {  
          const bytes \= cryptoMod.randomBytes(len);  
          for (let i \= 0; i \< len; i++) {  
            verifier \+= UNRESERVED\_CHARSET\[bytes\[i\] % charsetLen\];  
          }  
        } else {  
          for (let i \= 0; i \< len; i++) {  
            const idx \= Math.floor(Math.random() \* charsetLen);  
            verifier \+= UNRESERVED\_CHARSET\[idx\];  
          }  
        }  
      }  
      return verifier;  
    },

    /\*\*  
     \* Derives code challenge from verifier using S256 or plain  
     \*/  
    deriveCodeChallenge(verifier, method \= 'S256') {  
      if (\!verifier) return '';  
      if (method \=== 'plain') {  
        return verifier;  
      }  
      if (method \=== 'S256') {  
        const digestBytes \= sha256Sync(verifier);  
        return base64UrlEncode(digestBytes);  
      }  
      throw new Error(\`Unsupported code\_challenge\_method: \${method}\`);  
    },

    /\*\*  
     \* Validates that all characters in the verifier belong to RFC 7636 unreserved set  
     \*/  
    validateVerifierCharset(verifier) {  
      if (\!verifier) return { valid: false, invalidChars: \[\] };  
      const invalidChars \= \[\];  
      const regex \= /^\[A-Za-z0-9\\-.\_\~\]+\$/;  
      for (let i \= 0; i \< verifier.length; i++) {  
        const char \= verifier\[i\];  
        if (UNRESERVED\_CHARSET.indexOf(char) \=== \-1 && invalidChars.indexOf(char) \=== \-1) {  
          invalidChars.push(char);  
        }  
      }  
      return {  
        valid: invalidChars.length \=== 0,  
        invalidChars  
      };  
    },

    /\*\*  
     \* Calculates Shannon entropy and total bit entropy  
     \* log2(66) ≈ 6.044 bits per character  
     \*/  
    calculateEntropy(verifier) {  
      if (\!verifier || verifier.length \=== 0\) return { shannonEntropy: 0, totalBits: 0 };  
      const freq \= {};  
      for (let i \= 0; i \< verifier.length; i++) {  
        const c \= verifier\[i\];  
        freq\[c\] \= (freq\[c\] || 0\) \+ 1;  
      }  
      let shannon \= 0;  
      const len \= verifier.length;  
      for (const c in freq) {  
        const p \= freq\[c\] / len;  
        shannon \-= p \* (Math.log(p) / Math.LN2);  
      }  
      const totalBits \= Math.round(shannon \* len);  
      return {  
        shannonEntropy: parseFloat(shannon.toFixed(3)),  
        totalBits  
      };  
    },

    /\*\*  
     \* Builds the Authorization Request URL (RFC 7636 Section 4.3)  
     \*/  
    buildAuthorizeUrl(config) {  
      const endpoint \= config.authEndpoint || 'https\://auth.example.com/oauth/authorize';  
      const params \= new URLSearchParams();  
      params.set('response\_type', 'code');  
      params.set('client\_id', config.clientId || 'client\_demo\_123');  
      params.set('redirect\_uri', config.redirectUri || 'https\://app.example.com/oauth/callback');  
      params.set('scope', config.scope || 'openid profile email');  
      params.set('state', config.state || 'xyzStateSecure987');  
      params.set('code\_challenge', config.codeChallenge || '');  
      params.set('code\_challenge\_method', config.codeChallengeMethod || 'S256');

      return \`\${endpoint}?\${params.toString()}\`;  
    },

    /\*\*  
     \* Builds the Token Exchange Request Payload (RFC 7636 Section 4.5)  
     \*/  
    buildTokenRequest(config) {  
      return {  
        url: config.tokenEndpoint || 'https\://auth.example.com/oauth/token',  
        method: 'POST',  
        headers: {  
          'Content-Type': 'application/x-www-form-urlencoded'  
        },  
        body: {  
          grant\_type: 'authorization\_code',  
          client\_id: config.clientId || 'client\_demo\_123',  
          redirect\_uri: config.redirectUri || 'https\://app.example.com/oauth/callback',  
          code: config.code || 'splat\_code\_demo\_456',  
          code\_verifier: config.codeVerifier || ''  
        }  
      };  
    },

    /\*\*  
     \* Verifies that the submitted verifier matches the stored challenge  
     \*/  
    verifyExchange(verifier, storedChallenge, method \= 'S256') {  
      if (\!verifier || \!storedChallenge) return false;  
      const computed \= this.deriveCodeChallenge(verifier, method);  
      return computed \=== storedChallenge;  
    }  
  };

  return PKCEEngine;  
});  
