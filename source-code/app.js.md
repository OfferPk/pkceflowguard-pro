/\*\*  
 \* PKCEFlowGuard Pro \- Studio Application Orchestrator  
 \*/

// Global State  
let currentConfig \= {  
  clientId: 'bank\_mobile\_app\_prod\_9921',  
  authEndpoint: 'https\://identity.globalbank.com/oauth2/v2.0/authorize',  
  tokenEndpoint: 'https\://identity.globalbank.com/oauth2/v2.0/token',  
  redirectUri: 'https\://mobile.globalbank.com/auth/callback',  
  scope: 'openid profile email accounts:read transfers:execute',  
  codeVerifier: 'm8K9\_X-Z1p4Q7r2T5y8U3v6W9a2B4c6E8g0J2l4N6p8R0t2V4x6Z8-0b2d4f6h8j0l2n4p6r8t0v2x4z6-8a0c2e4g6i8k0m2o4q6s8u0w2y4.13579bdfhjlnprtvxzBDF',  
  codeChallenge: '',  
  codeChallengeMethod: 'S256',  
  state: 'SECURE\_CSRF\_TOKEN\_9a8b7c6d5e4f3a2b1c0d',  
  storageType: 'memory'  
};

let currentSimMode \= 'B'; // 'A' or 'B'  
let currentCodeTab \= 'ts'; // 'ts', 'node', 'swift', 'kotlin', 'python'

// Pre-defined Presets  
const PRESETS \= {  
  bank: {  
    clientId: 'bank\_mobile\_app\_prod\_9921',  
    authEndpoint: 'https\://identity.globalbank.com/oauth2/v2.0/authorize',  
    tokenEndpoint: 'https\://identity.globalbank.com/oauth2/v2.0/token',  
    redirectUri: 'https\://mobile.globalbank.com/auth/callback',  
    scope: 'openid profile email accounts:read transfers:execute',  
    codeVerifier: 'm8K9\_X-Z1p4Q7r2T5y8U3v6W9a2B4c6E8g0J2l4N6p8R0t2V4x6Z8-0b2d4f6h8j0l2n4p6r8t0v2x4z6-8a0c2e4g6i8k0m2o4q6s8u0w2y4.13579bdfhjlnprtvxzBDF',  
    codeChallengeMethod: 'S256',  
    state: 'SECURE\_CSRF\_TOKEN\_9a8b7c6d5e4f3a2b1c0d',  
    storageType: 'memory'  
  },  
  saas: {  
    clientId: 'saas\_cloudpulse\_spa\_441',  
    authEndpoint: 'https\://auth.cloudpulse.io/authorize',  
    tokenEndpoint: 'https\://auth.cloudpulse.io/oauth/token',  
    redirectUri: 'https\://app.cloudpulse.io/callback',  
    scope: 'openid profile email workspace:read',  
    codeVerifier: 'K9p2X-y4T7v9A1c3E5g7J9l1N3p5R7t9V1x3Z5-7b9d1f3h5j7l9n1p3r5t7v9x1z3A',  
    codeChallengeMethod: 'S256',  
    state: 'spa\_session\_state\_4412\_xyz',  
    storageType: 'sessionStorage'  
  },  
  vulnerable: {  
    clientId: 'legacy\_insecure\_client\_007',  
    authEndpoint: 'http\://insecure-auth.corp.local/oauth/authorize',  
    tokenEndpoint: 'http\://insecure-auth.corp.local/oauth/token',  
    redirectUri: 'http\://insecure-app.corp.local/callback',  
    scope: 'read',  
    codeVerifier: 'short\_plain\_verifier\!\#\$',  
    codeChallengeMethod: 'plain',  
    state: '',  
    storageType: 'localStorage'  
  }  
};

document.addEventListener('DOMContentLoaded', () \=\> {  
  // Bind inputs  
  document.getElementById('txtVerifier').addEventListener('input', (e) \=\> {  
    currentConfig.codeVerifier \= e.target.value;  
    updateVerifierMetrics();  
    deriveChallenge();  
    runLiveAudit();  
  });

  const inputs \= \['txtClientId', 'txtAuthEndpoint', 'txtTokenEndpoint', 'txtRedirectUri', 'txtState'\];  
  inputs.forEach(id \=\> {  
    document.getElementById(id).addEventListener('input', () \=\> {  
      syncConfigFromInputs();  
      runLiveAudit();  
    });  
  });

  // Initial load  
  loadPreset('bank');  
});

function syncConfigFromInputs() {  
  currentConfig.clientId \= document.getElementById('txtClientId').value;  
  currentConfig.authEndpoint \= document.getElementById('txtAuthEndpoint').value;  
  currentConfig.tokenEndpoint \= document.getElementById('txtTokenEndpoint').value;  
  currentConfig.redirectUri \= document.getElementById('txtRedirectUri').value;  
  currentConfig.state \= document.getElementById('txtState').value;  
  currentConfig.storageType \= document.getElementById('selStorage').value;  
}

function loadPreset(key) {  
  const p \= PRESETS\[key\];  
  if (\!p) return;

  \['btnPresetBank', 'btnPresetSaas', 'btnPresetVulnerable'\].forEach(id \=\> {  
    const el \= document.getElementById(id);  
    if (el) el.classList.remove('active');  
  });

  if (key \=== 'bank') document.getElementById('btnPresetBank')?.classList.add('active');  
  if (key \=== 'saas') document.getElementById('btnPresetSaas')?.classList.add('active');  
  if (key \=== 'vulnerable') document.getElementById('btnPresetVulnerable')?.classList.add('active');

  currentConfig \= JSON.parse(JSON.stringify(p));

  // Populate UI  
  document.getElementById('txtClientId').value \= currentConfig.clientId;  
  document.getElementById('txtAuthEndpoint').value \= currentConfig.authEndpoint;  
  document.getElementById('txtTokenEndpoint').value \= currentConfig.tokenEndpoint;  
  document.getElementById('txtRedirectUri').value \= currentConfig.redirectUri;  
  document.getElementById('txtState').value \= currentConfig.state;  
  document.getElementById('txtVerifier').value \= currentConfig.codeVerifier;  
  document.getElementById('selMethod').value \= currentConfig.codeChallengeMethod;  
  document.getElementById('selStorage').value \= currentConfig.storageType;

  const len \= currentConfig.codeVerifier.length;  
  document.getElementById('inputLengthSlider').value \= Math.max(43, Math.min(128, len));  
  document.getElementById('lenDisplay').innerText \= len;

  updateVerifierMetrics();  
  deriveChallenge();  
  runLiveAudit();  
}

function onSliderChange(val) {  
  document.getElementById('lenDisplay').innerText \= val;  
  const newVerifier \= PKCEEngine.generateCodeVerifier(parseInt(val, 10));  
  document.getElementById('txtVerifier').value \= newVerifier;  
  currentConfig.codeVerifier \= newVerifier;  
  updateVerifierMetrics();  
  deriveChallenge();  
  runLiveAudit();  
}

function generateNewPair() {  
  const len \= parseInt(document.getElementById('inputLengthSlider').value, 10\) || 64;  
  const newVerifier \= PKCEEngine.generateCodeVerifier(len);  
  document.getElementById('txtVerifier').value \= newVerifier;  
  currentConfig.codeVerifier \= newVerifier;  
  updateVerifierMetrics();  
  deriveChallenge();  
  runLiveAudit();  
}

function onMethodChange(val) {  
  currentConfig.codeChallengeMethod \= val;  
  const badge \= document.getElementById('methodBadge');  
  if (badge) {  
    badge.innerText \= \`METHOD: \${val}\`;  
    if (val \=== 'S256') {  
      badge.className \= 'badge badge-cyan';  
    } else {  
      badge.className \= 'badge badge-red';  
    }  
  }  
  deriveChallenge();  
  runLiveAudit();  
}

function deriveChallenge() {  
  const verifier \= currentConfig.codeVerifier;  
  const method \= currentConfig.codeChallengeMethod;  
  try {  
    const challenge \= PKCEEngine.deriveCodeChallenge(verifier, method);  
    currentConfig.codeChallenge \= challenge;  
    document.getElementById('txtChallenge').value \= challenge;  
  } catch (e) {  
    document.getElementById('txtChallenge').value \= 'ERROR: ' \+ e.message;  
  }  
}

function updateVerifierMetrics() {  
  const v \= currentConfig.codeVerifier || '';  
  const len \= v.length;  
  document.getElementById('metricLength').innerText \= len;  
  if (len \< 43 || len \> 128\) {  
    document.getElementById('metricLength').style.color \= 'var(--accent-red)';  
  } else {  
    document.getElementById('metricLength').style.color \= 'var(--accent-cyan)';  
  }

  const ent \= PKCEEngine.calculateEntropy(v);  
  document.getElementById('metricEntropy').innerText \= ent.totalBits;  
  if (ent.totalBits \>= 256\) {  
    document.getElementById('metricEntropy').style.color \= 'var(--accent-green)';  
  } else if (ent.totalBits \>= 150\) {  
    document.getElementById('metricEntropy').style.color \= 'var(--accent-amber)';  
  } else {  
    document.getElementById('metricEntropy').style.color \= 'var(--accent-red)';  
  }

  const cs \= PKCEEngine.validateVerifierCharset(v);  
  if (cs.valid && len \> 0\) {  
    document.getElementById('metricCharset').innerText \= 'Valid (66-ch)';  
    document.getElementById('metricCharset').style.color \= 'var(--accent-green)';  
  } else {  
    document.getElementById('metricCharset').innerText \= \`Invalid (\${cs.invalidChars.length})\`;  
    document.getElementById('metricCharset').style.color \= 'var(--accent-red)';  
  }  
}

function runLiveAudit() {  
  syncConfigFromInputs();  
  const report \= PKCEAuditor.audit(currentConfig);

  // Score & Grade banner  
  const gradeBadge \= document.getElementById('gradeBadge');  
  gradeBadge.innerText \= report.grade;  
  gradeBadge.className \= 'score-badge-huge grade-' \+ report.grade.toLowerCase().replace('+', 'plus');

  document.getElementById('scoreSummary').innerText \= \`Score: \${report.score} / 100\`;  
  document.getElementById('gradeSubtitle').innerText \= report.isProductionReady  
    ? 'RFC 7636 & OAuth 2.1 Fully Compliant'  
    : 'Remediation Required Before Production Release';

  const prodBadge \= document.getElementById('prodReadyBadge');  
  if (report.isProductionReady) {  
    prodBadge.innerText \= 'PRODUCTION READY';  
    prodBadge.className \= 'badge badge-green';  
  } else {  
    prodBadge.innerText \= 'SECURITY DEFICIENT';  
    prodBadge.className \= 'badge badge-red';  
  }

  // Render Checks  
  const listEl \= document.getElementById('checksList');  
  listEl.innerHTML \= '';  
  report.checks.forEach(chk \=\> {  
    const item \= document.createElement('div');  
    item.className \= 'check-item';

    const header \= document.createElement('div');  
    header.className \= 'check-header';

    const title \= document.createElement('div');  
    title.className \= 'check-title';  
    title.innerHTML \= \`\<span\>\${chk.passed ? '✅' : (chk.level \=== 'CRITICAL' ? '🛑' : '⚠️')}\</span\> \<span\>\${chk.title}\</span\>\`;

    const badge \= document.createElement('span');  
    badge.className \= \`badge \${chk.passed ? 'badge-green' : (chk.level \=== 'CRITICAL' ? 'badge-red' : 'badge-amber')}\`;  
    badge.innerText \= \`\${chk.points}/\${chk.maxPoints} pts\`;

    header.appendChild(title);  
    header.appendChild(badge);

    const msg \= document.createElement('div');  
    msg.className \= 'check-msg';  
    msg.innerText \= chk.message;

    item.appendChild(header);  
    item.appendChild(msg);

    if (\!chk.passed && chk.remediation) {  
      const rem \= document.createElement('div');  
      rem.className \= 'check-remediation';  
      rem.innerText \= '🔧 Remediation: ' \+ chk.remediation;  
      item.appendChild(rem);  
    }

    listEl.appendChild(item);  
  });

  // Render Protocol URLs  
  const authUrl \= PKCEEngine.buildAuthorizeUrl(currentConfig);  
  document.getElementById('boxAuthUrl').innerText \= authUrl;

  const tokenReq \= PKCEEngine.buildTokenRequest(currentConfig);  
  const tokenPayload \= \`\${tokenReq.method} \${tokenReq.url}\\nContent-Type: \${tokenReq.headers\['Content-Type'\]}\\n\\ngrant\_type=\${tokenReq.body.grant\_type}&\\nclient\_id=\${tokenReq.body.client\_id}&\\nredirect\_uri=\${encodeURIComponent(tokenReq.body.redirect\_uri)}&\\ncode=\${tokenReq.body.code}&\\ncode\_verifier=\${tokenReq.body.code\_verifier}\`;  
  document.getElementById('boxTokenReq').innerText \= tokenPayload;

  // Render Simulator & Code  
  renderSimulator();  
  renderCodeSynthesizer();  
}

function switchSimulator(mode) {  
  currentSimMode \= mode;  
  document.getElementById('btnSimA').classList.toggle('active', mode \=== 'A');  
  document.getElementById('btnSimB').classList.toggle('active', mode \=== 'B');  
  renderSimulator();  
}

function renderSimulator() {  
  const container \= document.getElementById('simContainer');  
  let sim;  
  if (currentSimMode \=== 'A') {  
    sim \= PKCESimulator.simulateScenarioA({  
      appName: 'Mobile Banking App',  
      redirectScheme: currentConfig.redirectUri,  
      method: currentConfig.codeChallengeMethod  
    });  
  } else {  
    sim \= PKCESimulator.simulateScenarioB({  
      appName: 'Mobile Banking App',  
      redirectScheme: currentConfig.redirectUri,  
      verifier: currentConfig.codeVerifier,  
      challenge: currentConfig.codeChallenge  
    });  
  }

  let html \= \`\<div style="margin-bottom: 12px; font-size: 13px; font-weight: 600; color: \${sim.severity \=== 'SECURE' ? 'var(--accent-green)' : 'var(--accent-red)'};"\>  
    \${sim.title} \- \${sim.impact}  
  \</div\>\<div class="sim-timeline"\>\`;

  sim.steps.forEach(st \=\> {  
    const isCompromised \= st.state \=== 'BREACH\_CONFIRMED' || st.state \=== 'CODE\_STOLEN';  
    const isSafe \= st.state \=== 'ATTACK\_NEUTRALIZED' || st.state \=== 'AUTHENTICATED\_SAFELY';  
    const borderClass \= isCompromised ? 'fail' : (isSafe ? 'success' : '');

    html \+= \`  
      \<div class="sim-step \${borderClass}"\>  
        \<div class="sim-step-head"\>  
          \<span\>Step \${st.stepNumber}: \${st.phase}\</span\>  
          \<span class="sim-step-actor"\>\[\${st.actor}\]\</span\>  
        \</div\>  
        \<div class="sim-step-desc"\>\${st.description}\</div\>  
        \<div class="sim-payload"\>\${st.payload}\</div\>  
      \</div\>  
    \`;  
  });

  html \+= '\</div\>';  
  container.innerHTML \= html;  
}

function switchCodeTab(tab) {  
  currentCodeTab \= tab;  
  \['tabTS', 'tabNode', 'tabSwift', 'tabKotlin', 'tabPython'\].forEach(id \=\> {  
    document.getElementById(id)?.classList.remove('active');  
  });

  if (tab \=== 'ts') document.getElementById('tabTS')?.classList.add('active');  
  if (tab \=== 'node') document.getElementById('tabNode')?.classList.add('active');  
  if (tab \=== 'swift') document.getElementById('tabSwift')?.classList.add('active');  
  if (tab \=== 'kotlin') document.getElementById('tabKotlin')?.classList.add('active');  
  if (tab \=== 'python') document.getElementById('tabPython')?.classList.add('active');

  renderCodeSynthesizer();  
}

function renderCodeSynthesizer() {  
  const codeEl \= document.getElementById('codeOutput');  
  let code \= '';  
  if (currentCodeTab \=== 'ts') {  
    code \= PKCECodeSynthesizer.generateBrowserTypeScript(currentConfig);  
  } else if (currentCodeTab \=== 'node') {  
    code \= PKCECodeSynthesizer.generateNodeJs(currentConfig);  
  } else if (currentCodeTab \=== 'swift') {  
    code \= PKCECodeSynthesizer.generateSwift(currentConfig);  
  } else if (currentCodeTab \=== 'kotlin') {  
    code \= PKCECodeSynthesizer.generateKotlin(currentConfig);  
  } else if (currentCodeTab \=== 'python') {  
    code \= PKCECodeSynthesizer.generatePython(currentConfig);  
  }  
  codeEl.innerText \= code;  
}

function copyToClipboard(elementId, alertId) {  
  const el \= document.getElementById(elementId);  
  if (\!el) return;  
  navigator.clipboard.writeText(el.value).then(() \=\> {  
    showAlert(alertId);  
  }).catch(() \=\> {  
    // Fallback  
    el.select();  
    document.execCommand('copy');  
    showAlert(alertId);  
  });  
}

function copyTextFromElement(elementId, alertId) {  
  const el \= document.getElementById(elementId);  
  if (\!el) return;  
  navigator.clipboard.writeText(el.innerText).then(() \=\> {  
    showAlert(alertId);  
  });  
}

function showAlert(alertId) {  
  const alertEl \= document.getElementById(alertId);  
  if (alertEl) {  
    alertEl.style.display \= 'inline';  
    setTimeout(() \=\> {  
      alertEl.style.display \= 'none';  
    }, 2000);  
  }  
}  
