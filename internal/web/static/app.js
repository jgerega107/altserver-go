'use strict';
const $ = id => document.getElementById(id);
let csrf = '', jobID = '', stream;
function notice(message) { $('notice').textContent = message; $('notice').hidden = !message; }
async function api(path, method = 'GET', body) {
 const headers = {};
 if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
 if (body && !(body instanceof FormData)) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(body); }
 const response = await fetch('/api/v1/' + path, {method, headers, body, credentials:'same-origin'});
 const result = await response.json();
 if (!response.ok) { if (response.status === 401) showLogin(); throw new Error(result.error || 'Request failed'); }
 return result;
}
function showLogin() { $('login').hidden = false; $('dashboard').hidden = true; if(stream) stream.close(); }
async function refresh() {
 const status = await api('status');
 $('status').textContent = `Server ${status.serverID} · Anisette: ${status.anisette} · Signing tool: ${status.signing}`;
 $('devices').replaceChildren(); $('device-select').replaceChildren();
 let devices;
 try { devices = await api('devices'); } catch(e) { $('devices').textContent = e.message; return; }
 if (!devices.length) $('devices').textContent = 'No devices detected. Check USB pairing and the host usbmuxd/netmuxd service.';
 for (const d of devices) {
  const div = document.createElement('div'); div.className = 'device';
  const text = document.createElement('p'); text.textContent = `${d.name} · ${d.connection}`; div.append(text);
  const enabled = (status.authorizedDevices || []).includes(d.udid);
  const button = document.createElement('button'); button.className = 'secondary'; button.textContent = enabled ? 'Disable refresh' : 'Enable refresh';
  button.onclick = async () => { try { await api('devices/authorize','POST',{udid:d.udid,enabled:!enabled}); await refresh(); } catch(e) { notice(e.message); } };
  div.append(button); $('devices').append(div);
  const option = document.createElement('option'); option.value = d.udid; option.textContent = d.name; $('device-select').append(option);
 }
}
async function loggedIn() { $('login').hidden = true; $('dashboard').hidden = false; await refresh(); const id = sessionStorage.getItem('jobID'); if(id) watch(id); }
$('login-form').onsubmit = async e => { e.preventDefault(); try { const f=e.currentTarget;const r=await api('login','POST',{password:f.elements.password.value});f.reset();csrf=r.csrf;notice('');await loggedIn(); } catch(e) { notice(e.message); } };
$('reload').onclick = () => refresh().catch(e=>notice(e.message));
$('logout').onclick = async () => { try {await api('logout','POST',{});csrf='';showLogin();} catch(e){notice(e.message);} };
$('install-form').onsubmit = async e => { e.preventDefault(); const f=e.currentTarget;const form=new FormData(f);$('install-button').disabled=true;notice('');try {const j=await api('jobs','POST',form);f.elements.password.value='';form.delete('password');watch(j.id);}catch(e){notice(e.message);$('install-button').disabled=false;} };
function renderJob(j) { $('job').hidden=false;$('job-message').textContent=j.message;$('progress').value=j.progress;$('code-form').hidden=j.state!=='needs_2fa';$('team-form').hidden=j.state!=='needs_team';if(j.state==='needs_team'){$('team-select').replaceChildren();for(const t of j.teams){const o=document.createElement('option');o.value=t.id;o.textContent=`${t.name} (${t.id})${t.free?' · Free':''}`;$('team-select').append(o);}}const done=['complete','failed','cancelled'].includes(j.state);$('cancel').hidden=done;$('install-button').disabled=!done;if(done){if(stream)stream.close();sessionStorage.removeItem('jobID');refresh().catch(e=>notice(e.message));} }
function watch(id) { jobID=id;sessionStorage.setItem('jobID',id);if(stream)stream.close();api('jobs/'+id).then(renderJob).catch(e=>{notice(e.message);sessionStorage.removeItem('jobID');});stream=new EventSource('/api/v1/jobs/'+id+'/events');stream.onmessage=e=>renderJob(JSON.parse(e.data));stream.onerror=()=>{api('jobs/'+id).then(renderJob).catch(e=>{notice(e.message);stream.close();});}; }
$('code-form').onsubmit=async e=>{e.preventDefault();try{await api(`jobs/${jobID}/code`,'POST',{value:e.currentTarget.elements.code.value});e.currentTarget.reset();$('code-form').hidden=true;}catch(e){notice(e.message);}};
$('team-form').onsubmit=async e=>{e.preventDefault();try{await api(`jobs/${jobID}/team`,'POST',{value:e.currentTarget.elements.team.value});$('team-form').hidden=true;}catch(e){notice(e.message);}};
$('cancel').onclick=()=>api(`jobs/${jobID}/cancel`,'POST',{}).catch(e=>notice(e.message));
api('session').then(r=>{csrf=r.csrf;return loggedIn();}).catch(e=>{if($('login').hidden)notice(e.message);});
