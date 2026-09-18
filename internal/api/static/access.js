'use strict';

async function managementAccessPage() {
  title('Management access policy', 'IP and subnet rules for the management port');
  if (me?.role !== 'administrator') {
    $('content').innerHTML='<div class="card">Administrator access required.</div>';
    return;
  }
  const version=renderVersion;
  const policy=await api('/api/v1/admin/access-policy');
  if (version!==renderVersion) return;
  policy.rules ||= [];
  let editing=-1;
  $('content').innerHTML=`<section class="card access-card">
    <h3>Management port only</h3>
    <p>These rules control access to the web panel and every HTTP API endpoint on the management port. NetFlow, IPFIX and sFlow listeners accept traffic from any source and are unaffected.</p>
    <p class="muted">The first matching enabled rule wins. Full access still requires a valid login and the user's permissions. A full block denies all management requests from that address. Apply changes to activate your rules.</p>
    <div class="field"><label>Addresses without a matching rule<select id="accessDefault"><option value="allow">Allow management access</option><option value="deny">Block management access</option></select></label></div>
    <p class="muted">If you choose Block, add an Allow rule for your own IP or subnet before applying.</p>
    <div id="accessRules" class="access-rules"></div>
    <h3 id="accessRuleHeading">Add an IP or subnet</h3>
    <form id="accessRuleForm"><div class="formgrid3">
      <div class="field"><label>IP address or subnet<input id="accessSource" placeholder="192.0.2.10 or 192.0.2.0/24" required maxlength="64"></label></div>
      <div class="field"><label>Action<select id="accessAction"><option value="allow">Full access</option><option value="deny">Full block</option></select></label></div>
      <div class="field"><label>Description (optional)<input id="accessName" maxlength="128" placeholder="Office network"></label></div>
    </div><div class="actions"><button id="accessAdd" type="submit">Add rule</button><button id="accessCancel" type="button" class="ghost hidden">Cancel edit</button></div></form>
    <div class="actions access-apply"><button id="saveAccessPolicy">Apply access policy</button><button id="resetAccessPolicy" class="ghost">Reload saved rules</button></div>
    <p id="accessPolicyResult" role="status" aria-live="polite"></p>
  </section>`;
  $('accessDefault').value=policy.default_action;
  const result=message=>{$('accessPolicyResult').textContent=message};
  const resetEditor=()=>{
    editing=-1;
    $('accessRuleForm').reset();
    $('accessRuleHeading').textContent='Add an IP or subnet';
    $('accessAdd').textContent='Add rule';
    $('accessCancel').classList.add('hidden');
  };
  const draw=()=>{
    $('accessRules').innerHTML=policy.rules.length?policy.rules.map((rule,i)=>`<article class="access-rule" data-rule-index="${i}">
      <div><b class="mono">${esc(rule.cidr)}</b><span class="pill ${rule.action==='allow'?'good':'bad'}">${rule.action==='allow'?'Full access':'Full block'}</span><small>${esc(rule.name||'No description')}</small></div>
      <div class="actions"><label class="access-enabled"><input type="checkbox" data-action="enabled" ${rule.enabled?'checked':''}>Enabled</label><button class="ghost small" data-action="up" aria-label="Move rule up" ${i===0?'disabled':''}>↑</button><button class="ghost small" data-action="down" aria-label="Move rule down" ${i===policy.rules.length-1?'disabled':''}>↓</button><button class="ghost small" data-action="edit">Edit</button><button class="ghost small" data-action="delete">Delete</button></div>
    </article>`).join(''):'<p class="muted">No rules. All addresses use the default action above.</p>';
  };
  draw();
  $('accessRules').onclick=event=>{
    const control=event.target.closest('[data-action]');
    if(!control)return;
    const i=Number(control.closest('[data-rule-index]').dataset.ruleIndex);
    const action=control.dataset.action;
    if(action==='edit'){
      editing=i;
      const rule=policy.rules[i];
      $('accessSource').value=rule.cidr;$('accessAction').value=rule.action;$('accessName').value=rule.name;
      $('accessRuleHeading').textContent='Edit rule';$('accessAdd').textContent='Update rule';$('accessCancel').classList.remove('hidden');$('accessSource').focus();
      return;
    }
    if(action==='enabled')policy.rules[i].enabled=control.checked;
    if(action==='delete')policy.rules.splice(i,1);
    if(action==='up'&&i>0)[policy.rules[i-1],policy.rules[i]]=[policy.rules[i],policy.rules[i-1]];
    if(action==='down'&&i<policy.rules.length-1)[policy.rules[i+1],policy.rules[i]]=[policy.rules[i],policy.rules[i+1]];
    resetEditor();draw();result('Unsaved changes. Apply access policy to activate.');
  };
  $('accessRuleForm').onsubmit=event=>{
    event.preventDefault();
    const source=$('accessSource').value.trim();
    const [ip,prefix,...rest]=source.split('/');
    const bits=ip.includes(':')?128:32;
    if(!validIP(ip)||rest.length||(prefix!==undefined&&(!/^\d+$/.test(prefix)||Number(prefix)>bits))){result('Enter a valid IPv4/IPv6 address or subnet.');return;}
    const rule={...(editing<0?{id:'rule-'+Array.from(crypto.getRandomValues(new Uint32Array(4)),v=>v.toString(16)).join(''),enabled:true}:policy.rules[editing]),cidr:source,action:$('accessAction').value,name:$('accessName').value.trim()};
    if(editing<0)policy.rules.push(rule);else policy.rules[editing]=rule;
    resetEditor();draw();result('Unsaved changes. Apply access policy to activate.');
  };
  $('accessCancel').onclick=resetEditor;
  $('accessDefault').onchange=()=>result('Unsaved changes. Apply access policy to activate.');
  $('saveAccessPolicy').onclick=async event=>{
    const button=event.currentTarget;button.disabled=true;
    try{
      policy.default_action=$('accessDefault').value;
      const saved=await api('/api/v1/admin/access-policy',{method:'POST',body:JSON.stringify(policy)});
      policy.rules=saved.rules||[];resetEditor();draw();result('Management access policy applied. Flow services are unchanged.');
    }catch(error){result(error.message)}finally{button.disabled=false}
  };
  $('resetAccessPolicy').onclick=()=>render();
}
