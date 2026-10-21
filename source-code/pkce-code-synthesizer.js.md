/\*\*  
 \* PKCEFlowGuard Pro \- Multi-Platform Code Synthesizer  
 \* Generates production-ready, zero-dependency PKCE client implementations for:  
 \* 1\. Browser SPA (TypeScript & Web Crypto API)  
 \* 2\. Node.js / Express (crypto module)  
 \* 3\. iOS Swift (CryptoKit & ASWebAuthenticationSession)  
 \* 4\. Android Kotlin (java.security.MessageDigest & CustomTabs)  
 \* 5\. Python 3 (hashlib & secrets)  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.PKCECodeSynthesizer \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const PKCECodeSynthesizer \= {  
    /\*\*  
     \* Browser SPA TypeScript / Web Crypto Implementation  
     \*/  
    generateBrowserTypeScript(config) {  
      const clientId \= config.clientId || 'your-client-id';  
      const authEndpoint \= config.authEndpoint || 'https\://auth.example.com/oauth/authorize';  
      const tokenEndpoint \= config.tokenEndpoint || 'https\://auth.example.com/oauth/token';  
      const redirectUri \= config.redirectUri || 'https\://app.example.com/callback';

      return \`// \==========================================  
// Browser SPA PKCE Client (TypeScript / Web Crypto)  
// \==========================================

export class PKCEClient {  
  private static readonly CHARSET \= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.\_\~';

  /\*\*  
   \* Generates a cryptographically secure random verifier (RFC 7636 Sec 4.1)  
   \*/  
  public static generateVerifier(length: number \= 64): string {  
    const validLength \= Math.max(43, Math.min(128, length));  
    const randomBytes \= new Uint8Array(validLength);  
    window.crypto.getRandomValues(randomBytes);  
    let verifier \= '';  
    for (let i \= 0; i \< validLength; i++) {  
      verifier \+= this.CHARSET\[randomBytes\[i\] % this.CHARSET.length\];  
    }  
    return verifier;  
  }

  /\*\*  
   \* Derives SHA-256 Code Challenge (RFC 7636 Sec 4.2)  
   \*/  
  public static async deriveChallenge(verifier: string): Promise\<string\> {  
    const encoder \= new TextEncoder();  
    const data \= encoder.encode(verifier);  
    const digest \= await window.crypto.subtle.digest('SHA-256', data);  
    return this.base64UrlEncode(new Uint8Array(digest));  
  }

  /\*\*  
   \* Base64URL encoding without padding (RFC 4648\)  
   \*/  
  private static base64UrlEncode(bytes: Uint8Array): string {  
    let binary \= '';  
    bytes.forEach(b \=\> binary \+= String.fromCharCode(b));  
    return btoa(binary)  
      .replace(/\\\\+/g, '-')  
      .replace(/\\\\//g, '\_')  
      .replace(/=+\$/, '');  
  }

  /\*\*  
   \* Builds the Authorization Redirect URL  
   \*/  
  public static async getAuthorizeUrl(scope: string \= 'openid profile email'): Promise\<{ url: string; verifier: string; state: string }\> {  
    const verifier \= this.generateVerifier(64);  
    const challenge \= await this.deriveChallenge(verifier);  
    const state \= this.generateVerifier(32);

    // Store in short-lived sessionStorage (cleared upon token exchange)  
    sessionStorage.setItem('pkce\_verifier', verifier);  
    sessionStorage.setItem('oauth\_state', state);

    const params \= new URLSearchParams({  
      response\_type: 'code',  
      client\_id: '\${clientId}',  
      redirect\_uri: '\${redirectUri}',  
      scope,  
      state,  
      code\_challenge: challenge,  
      code\_challenge\_method: 'S256'  
    });

    return {  
      url: \\\`\${authEndpoint}?\\\${params.toString()}\\\`,  
      verifier,  
      state  
    };  
  }

  /\*\*  
   \* Exchanges Authorization Code for Tokens at /token  
   \*/  
  public static async exchangeCodeForToken(code: string, returnedState: string): Promise\<any\> {  
    const storedState \= sessionStorage.getItem('oauth\_state');  
    const verifier \= sessionStorage.getItem('pkce\_verifier');

    if (\!storedState || storedState \!== returnedState) {  
      throw new Error('CSRF State mismatch detected\!');  
    }  
    if (\!verifier) {  
      throw new Error('PKCE verifier missing from session storage');  
    }

    sessionStorage.removeItem('pkce\_verifier');  
    sessionStorage.removeItem('oauth\_state');

    const body \= new URLSearchParams({  
      grant\_type: 'authorization\_code',  
      client\_id: '\${clientId}',  
      redirect\_uri: '\${redirectUri}',  
      code,  
      code\_verifier: verifier  
    });

    const response \= await fetch('\${tokenEndpoint}', {  
      method: 'POST',  
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },  
      body: body.toString()  
    });

    if (\!response.ok) {  
      const err \= await response.json();  
      throw new Error(\\\`Token exchange failed: \\\${err.error\_description || err.error}\\\`);  
    }

    return await response.json();  
  }  
}\`;  
    },

    /\*\*  
     \* Node.js Backend-For-Frontend Implementation  
     \*/  
    generateNodeJs(config) {  
      const clientId \= config.clientId || 'your-client-id';  
      const authEndpoint \= config.authEndpoint || 'https\://auth.example.com/oauth/authorize';  
      const tokenEndpoint \= config.tokenEndpoint || 'https\://auth.example.com/oauth/token';  
      const redirectUri \= config.redirectUri || 'https\://app.example.com/callback';

      return \`// \==========================================  
// Node.js Express / BFF PKCE Handler  
// \==========================================

const crypto \= require('crypto');

class NodePKCEHelper {  
  static CHARSET \= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.\_\~';

  static generateVerifier(length \= 64\) {  
    const len \= Math.max(43, Math.min(128, length));  
    const bytes \= crypto.randomBytes(len);  
    let verifier \= '';  
    for (let i \= 0; i \< len; i++) {  
      verifier \+= this.CHARSET\[bytes\[i\] % this.CHARSET.length\];  
    }  
    return verifier;  
  }

  static deriveChallenge(verifier) {  
    const hash \= crypto.createHash('sha256').update(verifier, 'ascii').digest();  
    return hash.toString('base64')  
      .replace(/\\\\+/g, '-')  
      .replace(/\\\\//g, '\_')  
      .replace(/=+\$/, '');  
  }

  static buildAuthUrl(session) {  
    const verifier \= this.generateVerifier(64);  
    const challenge \= this.deriveChallenge(verifier);  
    const state \= crypto.randomBytes(24).toString('hex');

    // Secure HttpOnly session binding  
    session.pkceVerifier \= verifier;  
    session.oauthState \= state;

    const params \= new URLSearchParams({  
      response\_type: 'code',  
      client\_id: '\${clientId}',  
      redirect\_uri: '\${redirectUri}',  
      scope: 'openid profile email',  
      state,  
      code\_challenge: challenge,  
      code\_challenge\_method: 'S256'  
    });

    return \\\`\${authEndpoint}?\\\${params.toString()}\\\`;  
  }

  static async exchangeToken(code, returnedState, session) {  
    if (\!session.oauthState || session.oauthState \!== returnedState) {  
      throw new Error('CSRF State mismatch');  
    }  
    const verifier \= session.pkceVerifier;  
    delete session.pkceVerifier;  
    delete session.oauthState;

    const body \= new URLSearchParams({  
      grant\_type: 'authorization\_code',  
      client\_id: '\${clientId}',  
      redirect\_uri: '\${redirectUri}',  
      code,  
      code\_verifier: verifier  
    });

    const res \= await fetch('\${tokenEndpoint}', {  
      method: 'POST',  
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },  
      body: body.toString()  
    });

    if (\!res.ok) {  
      throw new Error(\\\`Token exchange error: \\\${await res.text()}\\\`);  
    }  
    return await res.json();  
  }  
}

module.exports \= NodePKCEHelper;\`;  
    },

    /\*\*  
     \* iOS Swift Implementation (CryptoKit \+ ASWebAuthenticationSession)  
     \*/  
    generateSwift(config) {  
      const clientId \= config.clientId || 'mobile-ios-client';  
      const redirectUri \= config.redirectUri || 'myapp://oauth/callback';

      return \`// \==========================================  
// iOS Swift (CryptoKit & AuthenticationServices)  
// \==========================================

import Foundation  
import CryptoKit  
import AuthenticationServices

public final class PKCEAuthManager: NSObject {  
  private static let unreservedChars \= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.\_\~"

  public static func generateVerifier(length: Int \= 64\) \-\> String {  
    let clampedLength \= max(43, min(128, length))  
    var randomBytes \= \[UInt8\](repeating: 0, count: clampedLength)  
    \_ \= SecRandomCopyBytes(kSecRandomDefault, clampedLength, \&randomBytes)  
      
    let chars \= Array(unreservedChars)  
    return String(randomBytes.map { chars\[Int(\$0) % chars.count\] })  
  }

  public static func deriveChallenge(from verifier: String) \-\> String {  
    guard let data \= verifier.data(using: .ascii) else { return "" }  
    let digest \= SHA256.hash(data: data)  
    let base64 \= Data(digest).base64EncodedString()  
    return base64  
      .replacingOccurrences(of: "+", with: "-")  
      .replacingOccurrences(of: "/", with: "\_")  
      .replacingOccurrences(of: "=", with: "")  
  }

  public func startAuthFlow(anchor: ASPresentationAnchor, completion: @escaping (Result\<String, Error\>) \-\> Void) {  
    let verifier \= Self.generateVerifier(length: 64\)  
    let challenge \= Self.deriveChallenge(from: verifier)  
    let state \= UUID().uuidString

    var components \= URLComponents(string: "\${config.authEndpoint || 'https\://auth.example.com/oauth/authorize'}")\!  
    components.queryItems \= \[  
      URLQueryItem(name: "response\_type", value: "code"),  
      URLQueryItem(name: "client\_id", value: "\${clientId}"),  
      URLQueryItem(name: "redirect\_uri", value: "\${redirectUri}"),  
      URLQueryItem(name: "code\_challenge", value: challenge),  
      URLQueryItem(name: "code\_challenge\_method", value: "S256"),  
      URLQueryItem(name: "state", value: state)  
    \]

    guard let authUrl \= components.url else { return }

    let session \= ASWebAuthenticationSession(url: authUrl, callbackURLScheme: "myapp") { callbackURL, error in  
      if let error \= error {  
        completion(.failure(error))  
        return  
      }  
      guard let callbackURL \= callbackURL,  
            let queryItems \= URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems,  
            let code \= queryItems.first(where: { \$0.name \== "code" })?.value else {  
        return  
      }  
      // Pass code and verifier to token exchange  
      completion(.success(code))  
    }  
    session.presentationContextProvider \= self as? ASWebAuthenticationPresentationContextProviding  
    session.start()  
  }  
}\`;  
    },

    /\*\*  
     \* Android Kotlin Implementation (MessageDigest & CustomTabs)  
     \*/  
    generateKotlin(config) {  
      const clientId \= config.clientId || 'mobile-android-client';  
      const redirectUri \= config.redirectUri || 'myapp://oauth/callback';

      return \`// \==========================================  
// Android Kotlin (MessageDigest & Base64 URL\_SAFE)  
// \==========================================

package com.company.security.pkce

import android.util.Base64  
import java.security.MessageDigest  
import java.security.SecureRandom

object PKCEHelper {  
  private const val CHARSET \= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.\_\~"

  fun generateVerifier(length: Int \= 64): String {  
    val clamped \= length.coerceIn(43, 128\)  
    val random \= SecureRandom()  
    val bytes \= ByteArray(clamped)  
    random.nextBytes(bytes)  
    val chars \= CHARSET.toCharArray()  
    return (0 until clamped).map { chars\[(bytes\[it\].toInt() and 0xFF) % chars.size\] }.joinToString("")  
  }

  fun deriveChallenge(verifier: String): String {  
    val bytes \= verifier.toByteArray(Charsets.US\_ASCII)  
    val digest \= MessageDigest.getInstance("SHA-256").digest(bytes)  
    return Base64.encodeToString(digest, Base64.URL\_SAFE or Base64.NO\_WRAP or Base64.NO\_PADDING)  
  }

  fun buildAuthUri(authEndpoint: String \= "\${config.authEndpoint || 'https\://auth.example.com/oauth/authorize'}", verifier: String): String {  
    val challenge \= deriveChallenge(verifier)  
    return android.net.Uri.parse(authEndpoint).buildUpon()  
      .appendQueryParameter("response\_type", "code")  
      .appendQueryParameter("client\_id", "\${clientId}")  
      .appendQueryParameter("redirect\_uri", "\${redirectUri}")  
      .appendQueryParameter("code\_challenge", challenge)  
      .appendQueryParameter("code\_challenge\_method", "S256")  
      .appendQueryParameter("state", java.util.UUID.randomUUID().toString())  
      .build().toString()  
  }  
}\`;  
    },

    /\*\*  
     \* Python 3 Implementation (hashlib & secrets)  
     \*/  
    generatePython(config) {  
      const clientId \= config.clientId || 'python-client-id';  
      const redirectUri \= config.redirectUri || 'https\://app.example.com/callback';

      return \`\# \==========================================  
\# Python 3 PKCE Module (hashlib & secrets)  
\# \==========================================

import hashlib  
import base64  
import secrets  
import string  
import urllib.parse  
import requests

CHARSET \= string.ascii\_letters \+ string.digits \+ "-.\_\~"

def generate\_code\_verifier(length: int \= 64\) \-\> str:  
    """Generates an RFC 7636 compliant code\_verifier (43-128 chars)."""  
    valid\_len \= max(43, min(128, length))  
    return ''.join(secrets.choice(CHARSET) for \_ in range(valid\_len))

def derive\_code\_challenge(verifier: str) \-\> str:  
    """Calculates Base64URL-encoded SHA-256 code\_challenge."""  
    digest \= hashlib.sha256(verifier.encode('ascii')).digest()  
    return base64.urlsafe\_b64encode(digest).decode('ascii').rstrip('=')

def build\_auth\_url(auth\_endpoint: str \= "\${config.authEndpoint || 'https\://auth.example.com/oauth/authorize'}", client\_id: str \= "\${clientId}") \-\> tuple\[str, str, str\]:  
    verifier \= generate\_code\_verifier(64)  
    challenge \= derive\_code\_challenge(verifier)  
    state \= secrets.token\_urlsafe(24)

    params \= {  
        "response\_type": "code",  
        "client\_id": client\_id,  
        "redirect\_uri": "\${redirectUri}",  
        "scope": "openid profile email",  
        "state": state,  
        "code\_challenge": challenge,  
        "code\_challenge\_method": "S256"  
    }  
    url \= f"{auth\_endpoint}?{urllib.parse.urlencode(params)}"  
    return url, verifier, state

def exchange\_code\_for\_tokens(token\_endpoint: str, code: str, verifier: str, client\_id: str \= "\${clientId}") \-\> dict:  
    payload \= {  
        "grant\_type": "authorization\_code",  
        "client\_id": client\_id,  
        "redirect\_uri": "\${redirectUri}",  
        "code": code,  
        "code\_verifier": verifier  
    }  
    headers \= {"Content-Type": "application/x-www-form-urlencoded"}  
    resp \= requests.post(token\_endpoint, data=payload, headers=headers)  
    resp.raise\_for\_status()  
    return resp.json()  
\`;  
    }  
  };

  return PKCECodeSynthesizer;  
});  
