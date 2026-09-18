'use strict';

async function accountSecurityPage() {
  title('Account security','Password and two-step verification');
  const version=renderVersion;
  const passwordOnly=!!me.must_change;
  const status=passwordOnly?null:await api('/api/v1/auth/mfa/status');
  if(version!==renderVersion)return;
  const local=me.auth_source==='local'||!me.auth_source;
  $('content').innerHTML=`${passwordOnly?'<div class="notice">Change your temporary password before continuing.</div>':''}${needsMFA?'<div class="notice">Set up an authenticator, then sign in again to complete MFA verification.</div>':''}
    ${local?`<section class="card"><h3>Change password</h3><form id="accountPassword" class="account-form"><div class="formgrid3"><label>Current password<input id="currentPassword" type="password" autocomplete="current-password" required></label><label>New password<input id="newPassword" type="password" autocomplete="new-password" minlength="12" required></label><label>Confirm new password<input id="confirmPassword" type="password" autocomplete="new-password" minlength="12" required></label></div><p class="muted">Use at least 12 characters with uppercase, lowercase, a number and a symbol.</p><button>Change password and sign out</button><p id="passwordResult" role="status"></p></form></section>`:'<p>Your password is managed by your identity provider.</p>'}
    ${status?`<section class="card account-card"><h3>Authenticator</h3><p class="muted">Use <a href="https://support.google.com/accounts/answer/1066447" target="_blank" rel="noopener noreferrer">Google Authenticator</a> (Android / iOS) or <a href="https://support.microsoft.com/en-us/account-billing/add-personal-microsoft-accounts-to-the-microsoft-authenticator-app-92544b53-7706-4581-a142-30344a2a2a57" target="_blank" rel="noopener noreferrer">Microsoft Authenticator</a> (Android / iOS). Other apps supporting standard six-digit TOTP codes also work.</p><p>${status.totp_enabled?'Enabled':'Not enabled'} · ${status.recovery_codes} recovery codes remaining</p>${status.totp_enabled?'<form id="disableTOTP" class="account-form"><label>Authenticator or recovery code<input id="disableCode" autocomplete="one-time-code" required></label><button class="ghost">Disable authenticator</button></form>':'<button id="beginTOTP">Set up authenticator</button>'}<div id="totpEnrollment"></div><p id="totpResult" role="status"></p></section>`:''}`;
  $('accountPassword')?.addEventListener('submit',async event=>{
    event.preventDefault();
    const button=event.submitter;
    button.disabled=true;
    try {
      if($('newPassword').value!==$('confirmPassword').value)throw Error('New passwords do not match.');
      await api('/api/v1/auth/change-password',{method:'POST',body:JSON.stringify({old_password:$('currentPassword').value,new_password:$('newPassword').value})});
      showLogin();
      $('loginError').textContent='Password changed. Sign in with your new password.';
    } catch(e) {$('passwordResult').textContent=e.message}
    finally {button.disabled=false}
  });
  $('beginTOTP')?.addEventListener('click',async event=>{
    const button=event.currentTarget;
    button.disabled=true;
    try {
      const setup=await api('/api/v1/auth/mfa/totp/begin',{method:'POST',body:'{}'});
      $('totpEnrollment').innerHTML=`<div class="totp-setup"><img class="totp-qr" src="${esc(setup.qr_code)}" width="256" height="256" alt="Scan this QR code with your authenticator app"><div><h3>Scan to add your account</h3><p>In your mobile app, add an account and choose Scan a QR code. Then enter its six-digit code below.</p><details><summary>Cannot scan? Enter the setup key manually</summary><code class="totp-secret">${esc(setup.secret)}</code><p class="muted">Time based · 6 digits · 30 seconds · SHA-1</p></details></div></div><form id="confirmTOTP" class="account-form"><label>Six-digit code<input id="totpCode" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" required></label><button>Verify and enable</button></form>`;
      $('confirmTOTP').onsubmit=async event=>{
        event.preventDefault();
        const submit=event.submitter;
        submit.disabled=true;
        try {
          const result=await api('/api/v1/auth/mfa/totp/confirm',{method:'POST',body:JSON.stringify({code:$('totpCode').value})});
          $('totpEnrollment').innerHTML=`<p>${esc(result.warning)}</p><pre>${result.recovery_codes.map(esc).join('\n')}</pre><button id="mfaSignOut">I saved my codes — sign out</button>`;
          $('mfaSignOut').onclick=()=> $('logoutBtn').click();
          $('totpResult').textContent='Authenticator enabled. Sign in again with your code.';
        } catch(e) {$('totpResult').textContent=e.message;submit.disabled=false}
      };
    } catch(e) {$('totpResult').textContent=e.message;button.disabled=false}
  });
  $('disableTOTP')?.addEventListener('submit',async event=>{
    event.preventDefault();
    event.submitter.disabled=true;
    try {
      await api('/api/v1/auth/mfa/totp/disable',{method:'POST',body:JSON.stringify({code:$('disableCode').value})});
      await api('/api/v1/auth/logout',{method:'POST',body:'{}'});
      showLogin();
    } catch(e) {$('totpResult').textContent=e.message;event.submitter.disabled=false}
  });
}
