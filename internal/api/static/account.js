'use strict';

function passkeyBytes(value) {
  return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
}
function passkeyBase64(value) {
  return btoa(Array.from(new Uint8Array(value),v=>String.fromCharCode(v)).join('')).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function passkeyLogin() {
  const button=$('passkeyBtn');
  button.disabled=true;
  $('loginError').textContent='';
  try {
    const username=$('username').value.trim();
    if(!username)throw Error('Enter your username first.');
    const options=await api('/api/v1/auth/webauthn/assert/options',{method:'POST',signal:null,body:JSON.stringify({username})});
    const credential=await navigator.credentials.get({publicKey:{challenge:passkeyBytes(options.challenge),rpId:options.rp_id,allowCredentials:options.credential_ids.map(id=>({type:'public-key',id:passkeyBytes(id)})),userVerification:'required',timeout:60000}});
    if(!credential)throw Error('Passkey authentication was cancelled.');
    await api('/api/v1/auth/webauthn/assert/finish',{method:'POST',signal:null,body:JSON.stringify({username,assertion:{credential_id:passkeyBase64(credential.rawId),client_data_json:passkeyBase64(credential.response.clientDataJSON),authenticator_data:passkeyBase64(credential.response.authenticatorData),signature:passkeyBase64(credential.response.signature)}})});
    $('password').value='';
    $('mfaCode').value='';
    await boot();
  } catch(e) {$('loginError').textContent=e.message}
  finally {button.disabled=false}
}

async function accountSecurityPage() {
  title('Account security','Password, authenticator and passkeys');
  const version=renderVersion;
  const passwordOnly=!!me.must_change;
  const status=passwordOnly?null:await api('/api/v1/auth/mfa/status');
  if(version!==renderVersion)return;
  const local=me.auth_source==='local'||!me.auth_source;
  $('content').innerHTML=`${passwordOnly?'<div class="notice">Change your temporary password before continuing.</div>':''}${needsMFA?'<div class="notice">Set up an authenticator or passkey, then sign in again to complete MFA verification.</div>':''}
    ${local?`<section class="card"><h3>Change password</h3><form id="accountPassword"><label>Current password<input id="currentPassword" type="password" autocomplete="current-password" required></label><label>New password<input id="newPassword" type="password" autocomplete="new-password" minlength="12" required></label><label>Confirm new password<input id="confirmPassword" type="password" autocomplete="new-password" minlength="12" required></label><p class="muted">Use at least 12 characters with uppercase, lowercase, a number and a symbol.</p><button>Change password and sign out</button><p id="passwordResult" role="status"></p></form></section>`:'<p>Your password is managed by your identity provider.</p>'}
    ${status?`<section class="card"><h3>Authenticator</h3><p>${status.totp_enabled?'Enabled':'Not enabled'} · ${status.recovery_codes} recovery codes remaining</p>${status.totp_enabled?'<form id="disableTOTP"><label>Authenticator or recovery code<input id="disableCode" autocomplete="one-time-code" required></label><button class="ghost">Disable authenticator</button></form>':'<button id="beginTOTP">Set up authenticator</button>'}<div id="totpEnrollment"></div><p id="totpResult" role="status"></p></section><section class="card"><h3>Passkeys</h3><p>${status.passkeys} registered</p><button id="registerPasskey">Register this device</button><p id="passkeyResult" role="status"></p></section>`:''}`;
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
      $('totpEnrollment').innerHTML=`<p>Add this secret manually to your authenticator app:</p><pre>${esc(setup.secret)}</pre><form id="confirmTOTP"><label>Six-digit code<input id="totpCode" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" required></label><button>Verify and enable</button></form>`;
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
  const register=$('registerPasskey');
  if(register){
    register.disabled=!window.PublicKeyCredential||!window.isSecureContext;
    if(register.disabled)$('passkeyResult').textContent='Passkeys require HTTPS (or localhost) and a compatible browser.';
    register.onclick=async()=>{
      register.disabled=true;
      try {
        const options=await api('/api/v1/auth/webauthn/register/options',{method:'POST',body:'{}'});
        const credential=await navigator.credentials.create({publicKey:{challenge:passkeyBytes(options.challenge),rp:{id:options.rp_id,name:options.rp_name},user:{id:passkeyBytes(options.user_id),name:options.username,displayName:options.username},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{userVerification:'required'},attestation:'none',timeout:60000}});
        if(!credential)throw Error('Passkey registration was cancelled.');
        await api('/api/v1/auth/webauthn/register/finish',{method:'POST',body:JSON.stringify({client_data_json:passkeyBase64(credential.response.clientDataJSON),attestation_object:passkeyBase64(credential.response.attestationObject),name:'Browser passkey'})});
        $('passkeyResult').textContent='Passkey registered. You can sign out and sign in using Passkey.';
      } catch(e) {$('passkeyResult').textContent=e.message}
      finally {register.disabled=false}
    };
  }
}
