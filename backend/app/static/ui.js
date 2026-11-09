const $ = id => document.getElementById(id);
const state = {
  token: localStorage.getItem('sp_token') || '',
  user: null, folders: [], entries: [], roles: [], users: [],
  selectedFolderId: null, draggingFolderId: null, editingEntryId: null,
};

// ── Icons ─────────────────────────────────────────────────────────
const ICONS = [
  '🔑','🔐','🔒','🛡️','🗝️',
  '🐙','🦊','🐳','⚙️','🖥️','💻','🖨️','📡','🔌','🧩','⚡','🛠️',
  '☁️','🌐','🔗','📶','🌍','🏗️',
  '📧','📨','💬','📞','📟',
  '🏦','💳','💰','🪙',
  '🐦','💼','📘','📸','🎵','🎮','📺','🛒','📱','🎯',
  '🗄️','📦','📁','📂','🗃️','📋','📊','🔍',
  '🕵️','🔬','🧪','🚀','🌙','⭐',
];
function buildIconPicker() {
  const g=$('iconPickerGrid'); g.innerHTML='';
  ICONS.forEach(ic=>{ const d=document.createElement('div'); d.className='icon-opt'; d.textContent=ic; d.addEventListener('click',()=>{ selectIcon(ic); $('iconPickerGrid').classList.add('hidden'); }); g.appendChild(d); });
}
function buildSimpleIconPicker(gridId,onPick) {
  const g=$(gridId); g.innerHTML='';
  ICONS.forEach(ic=>{
    const d=document.createElement('div');
    d.className='icon-opt';
    d.textContent=ic;
    d.addEventListener('click',()=>onPick(ic));
    g.appendChild(d);
  });
}
function selectIcon(ic) {
  $('entryIconHidden').value=ic; $('entryIconPreview').textContent=ic;
  $('iconPickerGrid').querySelectorAll('.icon-opt').forEach(x=>x.classList.toggle('selected',x.textContent===ic));
}
function selectCreateFolderIcon(ic) {
  $('createFolderIconHidden').value=ic;
  $('createFolderIconPreview').textContent=ic;
  $('createFolderIconPickerGrid').querySelectorAll('.icon-opt').forEach(x=>x.classList.toggle('selected',x.textContent===ic));
}
function selectRenameFolderIcon(ic) {
  $('renameFolderIconHidden').value=ic;
  $('renameFolderIconPreview').textContent=ic;
  $('renameFolderIconPickerGrid').querySelectorAll('.icon-opt').forEach(x=>x.classList.toggle('selected',x.textContent===ic));
}

// ── Utils ─────────────────────────────────────────────────────────
function setMsg(id,t,e=false){ const n=$(id); n.textContent=t||''; n.classList.toggle('error',!!e); }
const openModal  = id => $(id).classList.add('open');
const closeModal = id => $(id).classList.remove('open');
function isSafeUrl(u){ try{ const p=new URL(u, location.origin).protocol; return p==='http:'||p==='https:'; }catch{ return false; } }
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function switchTab(tab) {
  $('tabVault').style.display = tab==='vault' ? 'flex' : 'none';
  $('tabAdmin').classList.toggle('hidden', tab!=='admin');
  $('tabAdmin').style.display = tab==='admin' ? 'flex' : '';
  $('navVault').classList.toggle('active', tab==='vault');
  $('navAdmin').classList.toggle('active', tab==='admin');
  const vaultOnly = tab==='vault';
  $('folderSectionHeader').classList.toggle('hidden', !vaultOnly);
  $('folderTree').classList.toggle('hidden', !vaultOnly);
  $('rootDropZone').style.display = 'none'; // only shown during folder drag
  if (tab==='admin') { loadAdminData(); loadLdapConfig(); }
}

function switchAdmin(sub) {
  ['ldap','smtp','users','backup','import','logs'].forEach(s=>{
    $('adminTab'+s[0].toUpperCase()+s.slice(1)).classList.toggle('hidden', s!==sub);
    $('adminNav'+s[0].toUpperCase()+s.slice(1)).classList.toggle('active', s===sub);
  });
  if (sub==='users') loadAdminUsers();
  else if (sub==='smtp') loadSmtpConfig();
  else if (sub==='logs') loadAuditLogs();
}

async function api(path, opts={}) {
  const h={'Content-Type':'application/json',...(opts.headers||{})};
  if (state.token) h.Authorization='Bearer '+state.token;
  const res=await fetch(path,{...opts,headers:h});
  const data=await res.json().catch(()=>({}));
  if (res.status===401 && state.token && path!=='/auth/login') {
    logout();
    setMsg('loginMsg','Session expired — please sign in again',true);
    throw new Error('Session expired');
  }
  if (!res.ok) throw new Error(data.detail||'Request failed');
  return data;
}

// ── DnD ───────────────────────────────────────────────────────────
function clearDropHL() {
  document.querySelectorAll('.folder-row.drop-target').forEach(n=>n.classList.remove('drop-target'));
  $('rootDropZone').classList.remove('active');
}
function getDragId(ev) {
  const n=Number(ev.dataTransfer?.getData('text/plain'));
  return Number.isFinite(n)&&n>0?n:state.draggingFolderId;
}
// Show root-drop zone only when dragging a folder (not an entry)
const showRoot=v=>{
  if (!v) { $('rootDropZone').style.display='none'; return; }
  // Only show if General exists as a target
  $('rootDropZone').style.display='block';
  $('rootDropZone').classList.toggle('visible',v);
};

// ── Stats ─────────────────────────────────────────────────────────
function visibleEntries() {
  const q=$('searchInput').value.trim().toLowerCase();
  let list=state.selectedFolderId==null?state.entries:state.entries.filter(e=>e.folder_id===state.selectedFolderId);
  if (q) list=list.filter(e=>(e.title+' '+e.login+' '+e.url+' '+e.description).toLowerCase().includes(q));
  return list;
}
function countUp(el, target, dur=600) {
  const start=parseInt(el.textContent)||0; if(start===target)return;
  const t0=performance.now();
  function step(now){
    const p=Math.min((now-t0)/dur,1);
    el.textContent=Math.round(start+(target-start)*p);
    if(p<1)requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}
function updateStats() {
  countUp($('statFolders'),state.folders.length);
  countUp($('statEntries'),state.entries.length);
  countUp($('statFiltered'),visibleEntries().length);
}

// ── Selects ───────────────────────────────────────────────────────
function fillParentSel(id,excl=null) {
  const s=$(id); s.innerHTML='';
  // "General" (system folder) acts as root
  const general=state.folders.find(f=>f.is_system);
  if (general && general.id!==excl) {
    s.appendChild(Object.assign(document.createElement('option'),{value:String(general.id),textContent:(general.icon||'📋')+' '+general.name+' (General)'}));
  } else {
    s.appendChild(Object.assign(document.createElement('option'),{value:'',textContent:'-- Root --'}));
  }
  // Regular folders
  const sorted=[...state.folders].filter(f=>!f.is_system).sort((a,b)=>a.name.localeCompare(b.name));
  for (const f of sorted) {
    if (f.id===excl) continue;
    const opt=document.createElement('option'); opt.value=String(f.id);
    opt.textContent=(f.icon||'📁')+' '+f.name;
    s.appendChild(opt);
  }
}
function fillSel(id,items,v,l) {
  const s=$(id); s.innerHTML='';
  for (const it of items)
    s.appendChild(Object.assign(document.createElement('option'),{value:it[v],textContent:it[l]}));
}

// ── Folder tree ───────────────────────────────────────────────────
function buildChildMap() {
  const m=new Map();
  for (const f of state.folders) {
    const k=f.parent_id==null?'root':String(f.parent_id);
    if (!m.has(k)) m.set(k,[]);
    m.get(k).push(f);
  }
  for (const a of m.values()) a.sort((a,b)=>a.name.localeCompare(b.name));
  return m;
}

function renderFolderTree() {
  const root=$('folderTree'); root.innerHTML='';
  if (!state.folders.length) { root.innerHTML='<div style="padding:8px 10px;font-size:12px;color:var(--muted)">No folders yet</div>'; return; }
  const cm=buildChildMap();
  const mkBranch=(pid,depth)=>{
    const k=pid==null?'root':String(pid);
    for (const f of (cm.get(k)||[])) {
      const item=document.createElement('div'); item.className='folder-item';
      const row=document.createElement('div');
      row.className='folder-row'+(state.selectedFolderId===f.id?' active':'');
      row.style.paddingLeft=(8+depth*16)+'px';
      row.style.cursor='pointer';

      // Full row click — not just name span
      row.addEventListener('click',ev=>{
        if (ev.target.closest('button')) return;
        state.selectedFolderId=f.id; renderFolderTree(); renderEntries();
      });

      const ico=document.createElement('span'); ico.className='f-icon';
      ico.textContent=f.is_system?(f.icon||'📋'):(f.icon||'📁');

      if (!f.is_system) {
        ico.draggable=true; ico.title='Drag to move';
        ico.addEventListener('dragstart',ev=>{
          state.draggingFolderId=f.id; ev.dataTransfer.effectAllowed='move';
          ev.dataTransfer.setData('text/plain',String(f.id));
          row.classList.add('drag-origin'); showRoot(true);
        });
        ico.addEventListener('dragend',()=>{ state.draggingFolderId=null; row.classList.remove('drag-origin'); showRoot(false); clearDropHL(); });
      }

      row.addEventListener('dragover',ev=>{
        const folderFrom=getDragId(ev);
        const entryId=ev.dataTransfer?.types?.includes('sp-entry-id');
        if(!folderFrom&&!entryId)return;
        if(folderFrom===f.id)return;
        ev.preventDefault(); row.classList.add('drop-target');
      });
      row.addEventListener('dragleave',()=>row.classList.remove('drop-target'));
      row.addEventListener('drop',async ev=>{
        ev.preventDefault(); row.classList.remove('drop-target'); clearDropHL();
        const entryIdStr=ev.dataTransfer.getData('sp-entry-id');
        if(entryIdStr){
          // Entry drop → move entry to this folder
          const entryId=Number(entryIdStr);
          const entry=state.entries.find(e=>e.id===entryId); if(!entry)return;
          try{
            await api('/entries/'+entryId,{method:'PUT',body:JSON.stringify({...entry,folder_id:f.id})});
            await loadEntries();
          }catch(e){alert(e.message);}
          return;
        }
        const from=getDragId(ev); if(!from||from===f.id)return;
        try{await moveFolderReq(from,f.id);}catch(e){alert(e.message);}
      });

      const nm=document.createElement('span'); nm.className='f-name';
      nm.textContent=f.name;
      if (f.is_system) nm.style.fontWeight='700';

      const cnt=state.entries.filter(e=>e.folder_id===f.id).length;
      const badge=Object.assign(document.createElement('span'),{className:'f-count',textContent:String(cnt)});

      const acts=document.createElement('div'); acts.className='f-actions';
      if (!f.is_system) {
        const mk=(title,ic,cls,fn)=>{ const b=document.createElement('button'); b.className='btn-icon'+cls; b.title=title; b.textContent=ic; b.onclick=ev=>{ev.stopPropagation();fn();}; return b; };
        acts.append(
          mk('Rename','✏️','',()=>{
            state.selectedFolderId=f.id;
            $('renameFolderName').value=f.name;
            selectRenameFolderIcon(f.icon||'📁');
            $('renameFolderIconPickerGrid').classList.add('hidden');
            setMsg('renameFolderMsg','');
            openModal('renameFolderModal');
          }),
          mk('Move','📦','',()=>{ state.selectedFolderId=f.id; fillParentSel('moveFolderParent',f.id); setMsg('moveFolderMsg',''); openModal('moveFolderModal'); }),
          mk('Delete','🗑️',' red',()=>{ state.selectedFolderId=f.id; $('deleteFolderTarget').textContent='Folder: '+f.name; $('deleteFolderStrategy').value='move_children_to_root'; setMsg('deleteFolderMsg',''); openModal('deleteFolderModal'); })
        );
      }
      row.append(ico,nm,badge,acts);
      item.appendChild(row); root.appendChild(item);
      mkBranch(f.id,depth+1);
    }
  };
  mkBranch(null,0);
}

async function moveFolderReq(folderId,parentId) {
  await api('/folders/'+folderId+'/move',{method:'PATCH',body:JSON.stringify({parent_id:parentId})});
  state.selectedFolderId=folderId;
  await loadFolders(); await loadEntries();
}

// ── Entry table ───────────────────────────────────────────────────
function renderEntries() {
  const tbody=$('entriesTbody'); tbody.innerHTML='';
  const fid=state.selectedFolderId;
  const fName=fid!=null?(state.folders.find(f=>f.id===fid)||{}).name:null;
  const fIcon=fid!=null?(state.folders.find(f=>f.id===fid)||{}).icon:null;

  // Section header + vault title
  if (fName) {
    $('entriesSectionTitle').innerHTML='<span class="entries-title-icon">'+esc(fIcon||'📁')+'</span><span>'+esc(fName.toUpperCase())+'</span>';
    $('vaultTitle').textContent=fName;
  } else {
    $('entriesSectionTitle').innerHTML='<span class="entries-title-icon">📂</span><span>Select a folder</span>';
    $('vaultTitle').textContent='Vault';
    tbody.innerHTML='<tr><td colspan="6"><div class="empty-state"><div class="big">📂</div>Select a folder in the sidebar</div></td></tr>';
    updateStats(); return;
  }

  const visible=visibleEntries();
  updateStats();
  if (!visible.length) {
    tbody.innerHTML='<tr><td colspan="6"><div class="empty-state"><div class="big">🗄️</div>No entries found</div></td></tr>';
    return;
  }
  const folderById=new Map(state.folders.map(f=>[f.id,f.name]));
  for (const e of visible) {
    const tr=document.createElement('tr');
    const bCls=e.entry_type_code==='ssh'?'type-badge ssh':e.entry_type_code==='api'?'type-badge api':'type-badge';
    const folderName=e.folder_id?folderById.get(e.folder_id)||'':null;
    let pwState=false;

    tr.innerHTML=
      '<td><div class="td-icon-title">'
      +'<span class="td-ico">'+esc(e.icon||'🔑')+'</span>'
      +'<div><div class="td-name">'+esc(e.title)+'</div>'
      +'</div></div></td>'
      +'<td><span class="'+bCls+'">'+esc(e.entry_type_code)+'</span></td>'
      +'<td class="td-login"><div class="td-field-row">'+(e.login?'<span>'+esc(e.login)+'</span>':'<span class="dash">—</span>')+'<div class="td-actions" id="lba_'+e.id+'"></div></div></td>'
      +'<td class="td-pw"><div class="td-field-row"><span class="pw-mask" id="pwm_'+e.id+'">&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;</span><div class="td-actions" id="pba_'+e.id+'"></div></div></td>'
      +'<td class="td-url">'+(e.url?(isSafeUrl(e.url)?'<a href="'+esc(e.url)+'" target="_blank" rel="noopener noreferrer" style="color:var(--accent);text-decoration:none">'+esc(e.url)+'</a>':'<span>'+esc(e.url)+'</span>'):'<span class="dash">—</span>')+'</td>'
      +'<td><div class="td-actions" id="tda_'+e.id+'"></div></td>';

    tr.setAttribute('draggable','true');
    tr.addEventListener('dragstart',ev=>{
      ev.dataTransfer.setData('sp-entry-id',String(e.id));
      ev.dataTransfer.effectAllowed='move';
      tr.style.opacity='0.45';
    });
    tr.addEventListener('dragend',()=>{ tr.style.opacity=''; clearDropHL(); });
    tr.addEventListener('dblclick', ev=>{ if (!ev.target.closest('button,a')) openEntryModal(e); });
    tbody.appendChild(tr);

    // Wire action buttons after DOM insert
    const acts=$('tda_'+e.id);
    const lbts=$('lba_'+e.id);
    const pbts=$('pba_'+e.id);
    const mkB=(title,ic,fn)=>{ const b=document.createElement('button'); b.className='btn-icon'; b.title=title; b.textContent=ic; b.addEventListener('click',fn); return b; };
    if (e.login) lbts.append(mkB('Copy login','📋',()=>{ navigator.clipboard.writeText(e.login); showCopyToast('Login'); }));
    pbts.append(
      mkB('Copy password','🔐',async()=>{
        try{ const d=await api('/entries/'+e.id+'/password'); await navigator.clipboard.writeText(d.password); showCopyToast('Password'); }
        catch(err){ alert(err.message); }
      })
    );
    acts.append(mkB('Edit','✏️',()=>openEntryModal(e)));
  }
}

// ── Entry modal ───────────────────────────────────────────────────
function openEntryModal(entry=null) {
  state.editingEntryId=entry?entry.id:null;
  $('entryModalTitle').textContent=entry?'✏️ Edit entry':'🔑 New entry';
  $('saveEntryBtn').textContent=entry?'Save changes':'Create';
  $('deleteEntryBtn').classList.toggle('hidden',!entry);
  setMsg('entryModalMsg','');
  $('iconPickerGrid').classList.add('hidden');
  document.querySelectorAll('#entryTypeTabs .type-tab').forEach(t=>t.classList.toggle('active',t.dataset.type===(entry?entry.entry_type_code:'password')));
  $('entryTypeHidden').value=entry?entry.entry_type_code:'password';
  selectIcon(entry?.icon||'🔑');
  fillParentSel('entryFolder');
  if (entry?.folder_id) $('entryFolder').value=String(entry.folder_id);
  else if (!entry&&state.selectedFolderId) $('entryFolder').value=String(state.selectedFolderId);
  // Level dropdown — only shown when user has access to more than General
  const lvls=state.user?.access_levels||['general'];
  const lvlLabels={general:'🟢 General',domain_admin:'🔵 Domain Admin',enterprise_admin:'🔴 Enterprise Admin'};
  $('entryLevel').innerHTML=lvls.map(lv=>`<option value="${esc(lv)}">${esc(lvlLabels[lv]||lv)}</option>`).join('');
  $('entryLevel').value=entry?.level||'general';
  const showLvl=lvls.length>1;
  $('entryLevelLabel').style.display=showLvl?'':'none';
  $('entryLevel').style.display=showLvl?'':'none';
  $('entryTitle').value=entry?.title||'';
  $('entryLogin').value=entry?.login||'';
  $('entryPassword').value='';
  $('entryPassword').type='password';
  if (entry) {
    $('entryPassword').placeholder='Loading…';
    api('/entries/'+entry.id+'/password').then(d=>{
      if (state.editingEntryId===entry.id) { $('entryPassword').value=d.password; $('entryPassword').placeholder=''; }
    }).catch(()=>{ $('entryPassword').placeholder=''; });
  }
  $('entryUrl').value=entry?.url||'';
  $('entryDesc').value=entry?.description||'';
  $('entryCreatedBy').textContent=entry?.created_by?'created by: '+entry.created_by:'';
  openModal('entryModal');
}

// ── Weak password detector ────────────────────────────────────────
function isWeakPassword(pw) {
  if (pw.length < 8) return true;
  if (/^[0-9]+$/.test(pw)) return true;          // all digits
  if (/^[a-zA-Z]+$/.test(pw)) return true;       // all letters, no digits/symbols
  if (!(/[A-Z]/.test(pw))) return true;           // no uppercase
  if (!(/[0-9]/.test(pw))) return true;           // no digit
  if (!(/[^a-zA-Z0-9]/.test(pw))) return true;   // no special char
  return false;
}
let _copyTimer = null;
function showCopyToast(label) {
  const t = $('copyToast');
  t.textContent = '✅ ' + label + ' copied';
  t.classList.add('show');
  if (_copyTimer) clearTimeout(_copyTimer);
  _copyTimer = setTimeout(()=>t.classList.remove('show'), 2000);
}
let _suckTimer = null;
function showSuckToast() {
  const t = $('suckToast');
  t.classList.add('show');
  if (_suckTimer) clearTimeout(_suckTimer);
  _suckTimer = setTimeout(()=>t.classList.remove('show'), 3000);
}

async function saveEntry() {
  const title=$('entryTitle').value.trim(), password=$('entryPassword').value;
  if (!title){setMsg('entryModalMsg','Enter a title',true);return;}
  if (!password && !state.editingEntryId){setMsg('entryModalMsg','Enter a password',true);return;}
  if (password && isWeakPassword(password)) showSuckToast();
  const folder_id=$('entryFolder').value?Number($('entryFolder').value):null;
  const level=$('entryLevel').value||'general';
  const body={title,password,login:$('entryLogin').value,url:$('entryUrl').value,
    description:$('entryDesc').value,entry_type_code:$('entryTypeHidden').value,
    folder_id,icon:$('entryIconHidden').value,level};
  try {
    if (state.editingEntryId) await api('/entries/'+state.editingEntryId,{method:'PUT',body:JSON.stringify(body)});
    else await api('/entries',{method:'POST',body:JSON.stringify(body)});
    closeModal('entryModal'); await loadEntries();
  } catch(e){setMsg('entryModalMsg',e.message,true);}
}

async function deleteEntry() {
  if (!state.editingEntryId||!confirm('Delete this entry?')) return;
  try{ await api('/entries/'+state.editingEntryId,{method:'DELETE'}); closeModal('entryModal'); await loadEntries(); }
  catch(e){setMsg('entryModalMsg',e.message,true);}
}

// ── Admin ─────────────────────────────────────────────────────────
async function loadLdapConfig() {
  try {
    const c = await api('/admin/ldap');
    $('ldapEnabled').checked      = c.enabled;
    $('ldapServerUrl').value      = c.server_url;
    $('ldapUseSsl').checked       = c.use_ssl;
    $('ldapBindDn').value         = c.bind_dn;
    $('ldapBindPassword').value   = '';
    $('ldapBindPassword').placeholder = c.bind_password_set ? '••• password saved — leave blank to keep •••' : '••• enter bind password •••';
    $('ldapBaseDn').value         = c.base_dn;
    $('ldapUserFilter').value     = c.user_filter;
    $('ldapUsernameAttr').value   = c.username_attr;
    $('ldapEmailAttr').value      = c.email_attr;
    $('ldapRequiredGroup').value  = c.required_group_dn;
    $('ldapAutoProvision').checked= c.auto_provision;
    $('ldapDefaultRole').value    = c.default_role;
  } catch {}
}

async function loadAdminRoles() {
  try {
    const [roles, types] = await Promise.all([api('/admin/roles'), api('/admin/entry-types')]);
    state.roles = roles;
    $('rolesTableBody').innerHTML='';
    roles.forEach(r=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+esc(r.name)+'</td><td style="color:var(--muted)"><small>'+esc(r.description)+'</small></td>';$('rolesTableBody').append(tr);});
    // Fill selects
    const ps=$('permRoleSelect'); ps.innerHTML='';
    roles.forEach(r=>ps.append(Object.assign(document.createElement('option'),{value:r.name,textContent:r.name})));
    const ts=$('permTypeSelect'); ts.innerHTML='';
    types.forEach(t=>ts.append(Object.assign(document.createElement('option'),{value:t.code,textContent:t.title+' ('+t.code+')'})));
  } catch{}
}

async function loadAdminUsers() {
  try {
    const users = await api('/admin/users');
    state.users = users;
    const SYSTEM_ROLES = ['General','DomainAdmin','EnterpriseAdmin'];
    $('usersTableBody').innerHTML='';
    users.forEach(u=>{
      const tr=document.createElement('tr');
      const roleBadges=u.roles.map(r=>'<span class="badge" style="background:#0e1e38;color:#6aa3d5;margin-right:3px">'+esc(r)+'</span>').join('');
      // Build assign dropdown from hardcoded system roles only
      const roleOpts=SYSTEM_ROLES.map(r=>'<option value="'+esc(r)+'">'+esc(r)+'</option>').join('');
      tr.innerHTML=
        '<td>'+esc(u.username)+'</td>'
        +'<td><span class="badge">'+esc(u.source)+'</span></td>'
        +'<td><span class="badge '+(u.is_superuser?'admin':'no')+'" id="adminBadge_'+u.id+'" style="cursor:pointer" title="Click to toggle admin">&#9881; '+(u.is_superuser?'yes':'no')+'</span></td>'
        +'<td><span class="badge '+(u.is_active?'yes':'no')+'">'+(u.is_active?'yes':'no')+'</span></td>'
        +'<td id="roles_'+u.id+'">'+roleBadges+'</td>'
        +'<td><div style="display:flex;gap:4px;align-items:center">'
        +'<select class="field" id="assignSel_'+u.id+'" style="padding:4px 6px;font-size:11px;width:110px"><option value="">+ role</option>'+roleOpts+'</select>'
        +'</div></td>';
      $('usersTableBody').append(tr);
      // Wire admin toggle
      const adminBadge=$('adminBadge_'+u.id);
      if(adminBadge){
        adminBadge.addEventListener('click',async()=>{
          if(!confirm((u.is_superuser?'Remove admin from ':'Make admin: ')+u.username+'?'))return;
          try{
            const d=await api('/admin/users/'+u.id+'/toggle-admin',{method:'POST'});
            u.is_superuser=d.is_superuser;
            adminBadge.className='badge '+(d.is_superuser?'admin':'no');
            adminBadge.textContent='⚙ '+(d.is_superuser?'yes':'no');
          }catch(e){alert(e.message);}
        });
      }
      // Wire assign select change
      const sel=$('assignSel_'+u.id);
      sel.addEventListener('change',async()=>{
        const rn=sel.value; if(!rn)return;
        try{
          await api('/admin/roles/assign',{method:'POST',body:JSON.stringify({username:u.username,role_name:rn})});
          await loadAdminUsers();
        } catch(e){ alert(e.message); sel.value=''; }
      });
      // Wire remove role badges
      tr.querySelectorAll('.badge[data-role]').forEach(b=>{
        b.style.cursor='pointer'; b.title='Click to remove';
        b.addEventListener('click',async()=>{
          if(!confirm('Remove role "'+b.dataset.role+'" from '+u.username+'?'))return;
          try{ await api('/admin/roles/unassign',{method:'POST',body:JSON.stringify({username:u.username,role_name:b.dataset.role})}); await loadAdminUsers(); }
          catch(e){alert(e.message);}
        });
      });
    });
    // Rebuild role badges with data-role for removal — redo after DOM insert
    users.forEach(u=>{
      const cell=$('roles_'+u.id); if(!cell)return;
      cell.innerHTML='';
      u.roles.forEach(r=>{
        const b=document.createElement('span'); b.className='badge';
        b.style.cssText='background:#0e1e38;color:#6aa3d5;margin-right:3px;cursor:pointer';
        b.title='Click to remove'; b.textContent=r; b.dataset.role=r;
        b.addEventListener('click',async()=>{
          if(!confirm('Remove role "'+r+'" from '+u.username+'?'))return;
          try{ await api('/admin/roles/unassign',{method:'POST',body:JSON.stringify({username:u.username,role_name:r})}); await loadAdminUsers(); }
          catch(e){alert(e.message);}
        });
        cell.append(b);
      });
    });
  } catch{}
}

async function loadAdminData() {
  // Called when admin tab opens — load the currently active sub-tab
  const active=['ldap','roles','users'].find(s=>!$('adminTab'+s[0].toUpperCase()+s.slice(1)).classList.contains('hidden'));
  if (active==='roles') await loadAdminRoles();
  else if (active==='users') await loadAdminUsers();
  // ldap loaded separately via loadLdapConfig
}

// ── Load ──────────────────────────────────────────────────────────
async function loadFolders() {
  state.folders=await api('/folders');
  // auto-select General (system) folder first, otherwise first folder
  if (state.selectedFolderId==null && state.folders.length) {
    const general=state.folders.find(f=>f.is_system);
    state.selectedFolderId=(general||state.folders[0]).id;
  }
  fillParentSel('createFolderParent'); fillParentSel('entryFolder');
  renderFolderTree(); updateStats();
}
async function loadEntries() { state.entries=await api('/entries'); renderFolderTree(); renderEntries(); }

// ── Auth ──────────────────────────────────────────────────────────
async function login() {
  const username=$('loginUsername').value.trim(), password=$('loginPassword').value;
  const remember=$('loginRemember').checked;
  if (!username||!password){setMsg('loginMsg','Enter username and password',true);return;}
  try {
    const d=await api('/auth/login',{method:'POST',body:JSON.stringify({username,password,remember_me:remember}),headers:{}});
    state.token=d.access_token; localStorage.setItem('sp_token',state.token);
    localStorage.setItem('sp_remember', remember ? 'true' : 'false');
    await bootstrapApp();
  } catch(e){setMsg('loginMsg',e.message,true);}
}

async function bootstrapApp() {
  $('loginRemember').checked = localStorage.getItem('sp_remember') === 'true';
  if (!state.token) return;
  try {
    state.user=await api('/users/me');
    $('loginScreen').classList.add('hidden');
    $('appShell').classList.remove('hidden');
    $('userAvatar').textContent=state.user.username[0].toUpperCase();
    $('userName').textContent=state.user.username;
    const lvlRoleLabel={general:'General',domain_admin:'Domain Admin',enterprise_admin:'Enterprise Admin'};
    const topLvl=state.user.access_levels?.slice(-1)[0];
    $('userRole').textContent=state.user.is_superuser?'Superuser':(topLvl?lvlRoleLabel[topLvl]||topLvl:'No role');
    if (state.user.is_superuser) $('navAdmin').classList.remove('hidden');
    initTheme();
    buildIconPicker();
    buildSimpleIconPicker('createFolderIconPickerGrid', ic=>{ selectCreateFolderIcon(ic); $('createFolderIconPickerGrid').classList.add('hidden'); });
    buildSimpleIconPicker('renameFolderIconPickerGrid', ic=>{ selectRenameFolderIcon(ic); $('renameFolderIconPickerGrid').classList.add('hidden'); });
    await Promise.all([loadFolders(),loadEntries()]);
    // Remember-me sessions (24h token) are not subject to the 5-minute idle logout
    if (localStorage.getItem('sp_remember') !== 'true') startIdleTracking();
  } catch(e) {
    localStorage.removeItem('sp_token'); state.token='';
    $('loginScreen').classList.remove('hidden'); $('appShell').classList.add('hidden');
    setMsg('loginMsg',e.message,true);
  }
}

function logout() {
  stopIdleTracking();
  localStorage.removeItem('sp_token');
  localStorage.removeItem('sp_remember');
  Object.assign(state,{token:'',user:null,folders:[],entries:[],roles:[],users:[],selectedFolderId:null});
  $('loginScreen').classList.remove('hidden'); $('appShell').classList.add('hidden');
  $('navAdmin').classList.add('hidden'); $('loginPassword').value=''; setMsg('loginMsg','');
}

// ── Events ────────────────────────────────────────────────────────
$('loginBtn').addEventListener('click',login);
$('loginUsername').addEventListener('keydown',ev=>{if(ev.key==='Enter')login();});
$('loginPassword').addEventListener('keydown',ev=>{if(ev.key==='Enter')login();});
$('loginPwEye').addEventListener('click',()=>{const f=$('loginPassword');f.type=f.type==='password'?'text':'password';});
$('logoutBtn').addEventListener('click',logout);

$('openFolderModalBtn').addEventListener('click',()=>{
  fillParentSel('createFolderParent');
  $('createFolderName').value='';
  selectCreateFolderIcon('📁');
  $('createFolderIconPickerGrid').classList.add('hidden');
  setMsg('createFolderMsg','');
  openModal('createFolderModal');
});
$('closeCreateFolderModalBtn').addEventListener('click',()=>closeModal('createFolderModal'));
$('saveCreateFolderBtn').addEventListener('click',async()=>{
  const name=$('createFolderName').value.trim(); if(!name){setMsg('createFolderMsg','Enter a name',true);return;}
  const pid=$('createFolderParent').value?Number($('createFolderParent').value):null;
  const icon=$('createFolderIconHidden').value||'📁';
  try{await api('/folders',{method:'POST',body:JSON.stringify({name,parent_id:pid,icon})});closeModal('createFolderModal');await loadFolders();}
  catch(e){setMsg('createFolderMsg',e.message,true);}
});

$('closeRenameFolderModalBtn').addEventListener('click',()=>closeModal('renameFolderModal'));
$('saveRenameFolderBtn').addEventListener('click',async()=>{
  const name=$('renameFolderName').value.trim(); if(!name){setMsg('renameFolderMsg','Enter a name',true);return;}
  const icon=$('renameFolderIconHidden').value||'📁';
  try{await api('/folders/'+state.selectedFolderId+'/rename',{method:'PUT',body:JSON.stringify({name,icon})});closeModal('renameFolderModal');await loadFolders();}
  catch(e){setMsg('renameFolderMsg',e.message,true);}
});

$('closeMoveFolderModalBtn').addEventListener('click',()=>closeModal('moveFolderModal'));
$('saveMoveFolderBtn').addEventListener('click',async()=>{
  const pid=$('moveFolderParent').value?Number($('moveFolderParent').value):null;
  try{await moveFolderReq(state.selectedFolderId,pid);closeModal('moveFolderModal');}
  catch(e){setMsg('moveFolderMsg',e.message,true);}
});

$('closeDeleteFolderModalBtn').addEventListener('click',()=>closeModal('deleteFolderModal'));
$('confirmDeleteFolderBtn').addEventListener('click',async()=>{
  const s=$('deleteFolderStrategy').value;
  try{await api('/folders/'+state.selectedFolderId,{method:'DELETE',body:JSON.stringify({strategy:s})});
    state.selectedFolderId=null;closeModal('deleteFolderModal');await loadFolders();await loadEntries();}
  catch(e){setMsg('deleteFolderMsg',e.message,true);}
});

$('rootDropZone').addEventListener('dragover',ev=>{const f=getDragId(ev);if(!f)return;ev.preventDefault();$('rootDropZone').classList.add('active');});
$('rootDropZone').addEventListener('dragleave',()=>$('rootDropZone').classList.remove('active'));
$('rootDropZone').addEventListener('drop',async ev=>{
  ev.preventDefault();const f=getDragId(ev);$('rootDropZone').classList.remove('active');showRoot(false);
  if(!f)return;
  // Drop onto General (system) folder
  const general=state.folders.find(fd=>fd.is_system);
  try{await moveFolderReq(f,general?general.id:null);}catch(e){alert(e.message);}
});

// ── Modal ESC + backdrop click ─────────────────────────────────────
document.addEventListener('keydown',ev=>{
  if(ev.key!=='Escape')return;
  document.querySelectorAll('.modal-backdrop.open').forEach(m=>m.classList.remove('open'));
});
document.querySelectorAll('.modal-backdrop').forEach(backdrop=>{
  backdrop.addEventListener('mousedown',ev=>{
    if(ev.target===backdrop) backdrop.classList.remove('open');
  });
});

$('addEntryBtn').addEventListener('click',()=>openEntryModal(null));
$('closeEntryModalBtn').addEventListener('click',()=>closeModal('entryModal'));
$('saveEntryBtn').addEventListener('click',saveEntry);
$('deleteEntryBtn').addEventListener('click',deleteEntry);
$('entryIconToggleBtn').addEventListener('click',()=>$('iconPickerGrid').classList.toggle('hidden'));
$('createFolderIconToggleBtn').addEventListener('click',()=>$('createFolderIconPickerGrid').classList.toggle('hidden'));
$('renameFolderIconToggleBtn').addEventListener('click',()=>$('renameFolderIconPickerGrid').classList.toggle('hidden'));
document.querySelectorAll('#entryTypeTabs .type-tab').forEach(tab=>{
  tab.addEventListener('click',()=>{
    document.querySelectorAll('#entryTypeTabs .type-tab').forEach(t=>t.classList.remove('active'));
    tab.classList.add('active'); $('entryTypeHidden').value=tab.dataset.type;
  });
});
$('genPasswordBtn').addEventListener('click',async()=>{
  try{const d=await api('/password/generate?length=24');$('entryPassword').value=d.password;$('entryPassword').type='text';}catch{}
});
$('entryPwEye').addEventListener('click',()=>{const f=$('entryPassword');f.type=f.type==='password'?'text':'password';});

$('searchInput').addEventListener('input',()=>renderEntries());
$('refreshEntriesBtn').addEventListener('click',async()=>{await Promise.all([loadFolders(),loadEntries()]);});

$('createRoleBtn').addEventListener('click',async()=>{
  const name=$('roleNameInput').value.trim(); if(!name){setMsg('createRoleMsg','Enter role name',true);return;}
  try{await api('/admin/roles',{method:'POST',body:JSON.stringify({name,description:$('roleDescInput').value})});
    setMsg('createRoleMsg','Created!');$('roleNameInput').value='';$('roleDescInput').value='';await loadAdminRoles();}
  catch(e){setMsg('createRoleMsg',e.message,true);}
});
$('savePermBtn').addEventListener('click',async()=>{
  const rn=$('permRoleSelect').value,et=$('permTypeSelect').value;
  if(!rn){setMsg('savePermMsg','Select a role',true);return;}
  try{await api('/admin/permissions',{method:'POST',body:JSON.stringify({role_name:rn,entry_type_code:et,can_read:$('permCanRead').checked,can_write:$('permCanWrite').checked})});
    setMsg('savePermMsg','Saved!');}
  catch(e){setMsg('savePermMsg',e.message,true);}
});
$('refreshUsersBtn').addEventListener('click',loadAdminUsers);

// ── Backup ────────────────────────────────────────────────────────
$('createBackupBtn').addEventListener('click',async()=>{
  const pw=$('backupPassword').value;
  if(!pw){setMsg('backupMsg','Enter a backup password',true);return;}
  setMsg('backupMsg','Creating backup…');
  try{
    const fd=new FormData(); fd.append('password',pw);
    const res=await fetch('/admin/backup',{method:'POST',headers:{Authorization:'Bearer '+state.token},body:fd});
    if(!res.ok){const d=await res.json().catch(()=>({}));throw new Error(d.detail||'Backup failed');}
    const blob=await res.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url; a.download='suckpasswords.spbackup'; a.click();
    URL.revokeObjectURL(url);
    setMsg('backupMsg','Backup downloaded!');
  }catch(e){setMsg('backupMsg',e.message,true);}
});

$('restoreBackupBtn').addEventListener('click',async()=>{
  const file=$('restoreFile').files[0], pw=$('restorePassword').value;
  if(!file){setMsg('restoreMsg','Select a backup file',true);return;}
  if(!pw){setMsg('restoreMsg','Enter the decryption password',true);return;}
  if(!confirm('This will DELETE all existing entries and replace them from the backup. Continue?'))return;
  setMsg('restoreMsg','Restoring…');
  try{
    const fd=new FormData(); fd.append('password',pw); fd.append('file',file);
    const d=await fetch('/admin/restore',{method:'POST',headers:{Authorization:'Bearer '+state.token},body:fd})
      .then(async r=>{const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.detail||'Restore failed');return j;});
    setMsg('restoreMsg',`Restored ${d.imported} entries (${d.skipped} skipped)`);
    await loadEntries();
  }catch(e){setMsg('restoreMsg',e.message,true);}
});

// ── Export / Import CSV ────────────────────────────────────────────
$('exportCsvBtn').addEventListener('click',async()=>{
  setMsg('exportMsg','Exporting…');
  try{
    const res=await fetch('/admin/export/csv',{headers:{Authorization:'Bearer '+state.token}});
    if(!res.ok){const d=await res.json().catch(()=>({}));throw new Error(d.detail||'Export failed');}
    const blob=await res.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download='suckpasswords_import_template.csv'; a.click();
    URL.revokeObjectURL(url);
    setMsg('exportMsg','Exported!');
  }catch(e){setMsg('exportMsg',e.message,true);}
});

$('importCsvBtn').addEventListener('click',async()=>{
  const file=$('importCsvFile').files[0];
  if(!file){setMsg('importMsg','Select a CSV file',true);return;}
  setMsg('importMsg','Importing…');
  try{
    const fd=new FormData(); fd.append('file',file);
    const d=await fetch('/admin/import/csv',{method:'POST',headers:{Authorization:'Bearer '+state.token},body:fd})
      .then(async r=>{const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.detail||'Import failed');return j;});
    setMsg('importMsg',`Imported ${d.imported} entries (${d.skipped} skipped)`);
    await loadEntries();
  }catch(e){setMsg('importMsg',e.message,true);}
});

// ── SMTP ──────────────────────────────────────────────────────────
async function loadSmtpConfig() {
  try {
    const c = await api('/admin/smtp');
    $('smtpEnabled').checked         = c.enabled;
    $('smtpHost').value              = c.host;
    $('smtpPort').value              = c.port;
    $('smtpUseTls').checked          = c.use_tls;
    $('smtpUseSsl').checked          = c.use_ssl;
    $('smtpAnonymous').checked       = !!c.anonymous;
    $('smtpUsername').value          = c.username;
    $('smtpPassword').value          = '';
    $('smtpPassword').placeholder    = c.password_set ? '••• password saved — leave blank to keep •••' : '••• enter SMTP password •••';
    $('smtpFromEmail').value         = c.from_email;
    $('smtpFromName').value          = c.from_name;
    $('smtpNotifyCreate').checked    = c.notify_on_create;
    $('smtpNotifyUpdate').checked    = c.notify_on_update;
    $('smtpNotifyDelete').checked    = c.notify_on_delete;
    setSmtpAuthFieldsState();
  } catch {}
}

function setSmtpAuthFieldsState() {
  const disabled = $('smtpAnonymous').checked;
  $('smtpUsername').disabled = disabled;
  $('smtpPassword').disabled = disabled;
  if (disabled) {
    $('smtpPassword').value = '';
  }
}

$('saveSmtpBtn')?.addEventListener('click',async()=>{
  const body={
    enabled:$('smtpEnabled').checked,
    host:$('smtpHost').value.trim(),
    port:Number($('smtpPort').value)||587,
    use_tls:$('smtpUseTls').checked,
    use_ssl:$('smtpUseSsl').checked,
    anonymous:$('smtpAnonymous').checked,
    username:$('smtpUsername').value.trim(),
    password:$('smtpPassword').value||null,
    from_email:$('smtpFromEmail').value.trim(),
    from_name:$('smtpFromName').value.trim()||'SuckPasswords',
    notify_on_create:$('smtpNotifyCreate').checked,
    notify_on_update:$('smtpNotifyUpdate').checked,
    notify_on_delete:$('smtpNotifyDelete').checked,
  };
  try{await api('/admin/smtp',{method:'PUT',body:JSON.stringify(body)});setMsg('smtpMsg','Saved!');await loadSmtpConfig();}
  catch(e){setMsg('smtpMsg',e.message,true);}
});
$('testSmtpBtn')?.addEventListener('click',async()=>{
  setMsg('smtpMsg','Sending test email\u2026');
  try{
    const d=await api('/admin/smtp/test',{method:'POST',body:JSON.stringify({to_email:$('smtpTestTo').value.trim()})});
    setMsg('smtpMsg','\u2705 '+d.message);
  } catch(e){setMsg('smtpMsg','\u274c '+e.message,true);}
});

// ── Audit logs ────────────────────────────────────────────────────
let _logsCache = [];
async function loadAuditLogs() {
  try {
    setMsg('logsMsg','Loading\u2026');
    _logsCache = await api('/admin/logs?limit=200');
    renderAuditLogs();
    setMsg('logsMsg','');

$('smtpAnonymous')?.addEventListener('change',setSmtpAuthFieldsState);
  } catch(e){ setMsg('logsMsg',e.message,true); }
}
function renderAuditLogs() {
  const tb=$('logsTableBody'); tb.innerHTML='';
  const q=($('logsFilter').value||'').trim().toLowerCase();
  const rows=q
    ? _logsCache.filter(r=>(r.username+' '+r.action+' '+r.resource_type+' '+r.resource_id+' '+r.details).toLowerCase().includes(q))
    : _logsCache;
  if (!rows.length) {
    tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px">No log entries</td></tr>';
    return;
  }
  for (const r of rows) {
    const tr=document.createElement('tr');
    let ts=r.created_at||'';
    try { ts = new Date(r.created_at).toLocaleString(); } catch {}
    const resource = r.resource_type
      ? esc(r.resource_type)+(r.resource_id?(' #'+esc(r.resource_id)):'')
      : '';
    tr.innerHTML =
      '<td style="white-space:nowrap;font-size:12px;color:var(--muted)">'+esc(ts)+'</td>'
      +'<td>'+esc(r.username||'-')+'</td>'
      +'<td><span class="badge">'+esc(r.action)+'</span></td>'
      +'<td>'+resource+'</td>'
      +'<td style="font-size:12px;color:var(--muted)">'+esc(r.details||'')+'</td>';
    tb.appendChild(tr);
  }
}
$('refreshLogsBtn')?.addEventListener('click',loadAuditLogs);
$('logsFilter')?.addEventListener('input',renderAuditLogs);

$('saveLdapBtn').addEventListener('click',async()=>{
  const body={
    enabled:$('ldapEnabled').checked,
    server_url:$('ldapServerUrl').value.trim(),
    use_ssl:$('ldapUseSsl').checked,
    bind_dn:$('ldapBindDn').value.trim(),
    bind_password:$('ldapBindPassword').value||null,
    base_dn:$('ldapBaseDn').value.trim(),
    user_filter:$('ldapUserFilter').value.trim()||'(sAMAccountName={username})',
    username_attr:$('ldapUsernameAttr').value.trim()||'sAMAccountName',
    email_attr:$('ldapEmailAttr').value.trim()||'mail',
    required_group_dn:$('ldapRequiredGroup').value.trim(),
    auto_provision:$('ldapAutoProvision').checked,
    default_role:$('ldapDefaultRole').value.trim(),
  };
  try{await api('/admin/ldap',{method:'PUT',body:JSON.stringify(body)});setMsg('ldapMsg','Saved!');await loadLdapConfig();}
  catch(e){setMsg('ldapMsg',e.message,true);}
});
$('testLdapBtn').addEventListener('click',async()=>{
  setMsg('ldapMsg','Testing\u2026');
  try{const d=await api('/admin/ldap/test',{method:'POST'});setMsg('ldapMsg','\u2705 '+d.message);}
  catch(e){setMsg('ldapMsg','\u274c '+e.message,true);}
});
$('syncLdapBtn').addEventListener('click',async()=>{
  setMsg('ldapMsg','Syncing\u2026');
  try{
    const d=await api('/admin/ldap/sync',{method:'POST'});
    const parts=['\u2705 '+d.message,'found: '+d.total_found,'created: '+d.created];
    if(d.skipped_already_exists) parts.push('already exist: '+d.skipped_already_exists);
    if(d.skipped_no_username_attr) parts.push('no username attr: '+d.skipped_no_username_attr);
    if(d.skipped_not_in_group) parts.push('not in group: '+d.skipped_not_in_group);
    if(d.deleted_not_in_group) parts.push('deleted (not in group): '+d.deleted_not_in_group);
    setMsg('ldapMsg',parts.join(' | '));
  }
  catch(e){setMsg('ldapMsg','\u274c '+e.message,true);}
});

// ── Sidebar resize ──────────────────────────────────────────────
(function(){
  const sb=$('sidebar'), rz=$('sidebarResizer');
  const STOR='sp_sidebar_w';
  const saved=parseInt(localStorage.getItem(STOR),10);
  if (saved&&saved>=160&&saved<=480) sb.style.width=saved+'px';
  let startX=0, startW=0;
  rz.addEventListener('mousedown',ev=>{
    ev.preventDefault(); startX=ev.clientX; startW=sb.offsetWidth;
    rz.classList.add('dragging'); document.body.style.cursor='col-resize'; document.body.style.userSelect='none';
    const onMove=mv=>{ const w=Math.min(480,Math.max(160,startW+(mv.clientX-startX))); sb.style.width=w+'px'; };
    const onUp=()=>{ rz.classList.remove('dragging'); document.body.style.cursor=''; document.body.style.userSelect='';
      localStorage.setItem(STOR,sb.offsetWidth); document.removeEventListener('mousemove',onMove); document.removeEventListener('mouseup',onUp); };
    document.addEventListener('mousemove',onMove); document.addEventListener('mouseup',onUp);
  });
})();

bootstrapApp();

// ── Theme ─────────────────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const icon = $('themeToggleBtn').querySelector('.ico');
  if (icon) icon.textContent = theme === 'light' ? '🌙' : '☀️';
  localStorage.setItem('sp_theme_' + (state.user?.username || '_'), theme);
}
function initTheme() {
  const saved = localStorage.getItem('sp_theme_' + (state.user?.username || '_')) || 'dark';
  applyTheme(saved);
}
$('themeToggleBtn').addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
});

// ── Inactivity auto-logout ────────────────────────────────────────
const IDLE_MS = 5 * 60 * 1000;   // 5 minutes total idle window
const WARN_MS = 30 * 1000;        // show warning 30 s before logout
let _idleTimer = null, _warnTimer = null, _warnInterval = null;

function _idleActivity() {
  if (!state.token) return;
  clearTimeout(_idleTimer);
  clearTimeout(_warnTimer);
  clearInterval(_warnInterval);
  $('idleWarning').classList.add('hidden');
  _warnTimer = setTimeout(_showIdleWarning, IDLE_MS - WARN_MS);
  _idleTimer = setTimeout(() => {
    stopIdleTracking();
    logout();
    setMsg('loginMsg', 'Session expired — logged out due to inactivity', true);
  }, IDLE_MS);
}

function _showIdleWarning() {
  let secs = Math.round(WARN_MS / 1000);
  $('idleCountdown').textContent = secs;
  $('idleWarning').classList.remove('hidden');
  clearInterval(_warnInterval);
  _warnInterval = setInterval(() => {
    secs--;
    $('idleCountdown').textContent = Math.max(secs, 0);
    if (secs <= 0) clearInterval(_warnInterval);
  }, 1000);
}

const _IDLE_EVENTS = ['mousemove','mousedown','keydown','touchstart','scroll','click'];

function startIdleTracking() {
  _IDLE_EVENTS.forEach(ev => window.addEventListener(ev, _idleActivity, {passive:true}));
  _idleActivity();
}

function stopIdleTracking() {
  clearTimeout(_idleTimer); clearTimeout(_warnTimer); clearInterval(_warnInterval);
  $('idleWarning').classList.add('hidden');
  _IDLE_EVENTS.forEach(ev => window.removeEventListener(ev, _idleActivity));
}

$('idleStayBtn').addEventListener('click', _idleActivity);

// ── About modal ───────────────────────────────────────────────────
$('aboutBtn').addEventListener('click', () => openModal('aboutModal'));
$('closeAboutModalBtn').addEventListener('click', () => closeModal('aboutModal'));

// ── Particle network background ───────────────────────────────────
(function(){
  const canvas=$('bgCanvas'), ctx=canvas.getContext('2d');
  let W,H,raf;
  const mouse={x:-9999,y:-9999};
  const N=65;
  const P=[];

  function resize(){
    W=canvas.width=window.innerWidth;
    H=canvas.height=window.innerHeight;
  }
  window.addEventListener('resize',resize);
  window.addEventListener('mousemove',e=>{mouse.x=e.clientX;mouse.y=e.clientY;});

  function mkP(){
    return{
      x:Math.random()*W, y:Math.random()*H,
      vx:(Math.random()-.5)*.35, vy:(Math.random()-.5)*.35,
      r:Math.random()*1.4+.6
    };
  }

  function init(){resize(); P.length=0; for(let i=0;i<N;i++) P.push(mkP());}

  function isDark(){return (document.documentElement.getAttribute('data-theme')||'dark')==='dark';}

  function draw(){
    ctx.clearRect(0,0,W,H);
    const dark=isDark();
    const dotColor  = dark ? 'rgba(74,108,247,0.55)'  : 'rgba(74,108,247,0.25)';
    const lineColor = dark ? 'rgba(74,108,247,0.10)'  : 'rgba(74,108,247,0.06)';
    const mouseColor= dark ? 'rgba(74,158,255,0.50)'  : 'rgba(74,108,247,0.20)';
    const LINK=130, MOUSE=160;

    for(let i=0;i<N;i++){
      const p=P[i];
      // mouse soft attraction
      const mdx=mouse.x-p.x, mdy=mouse.y-p.y;
      const md=Math.sqrt(mdx*mdx+mdy*mdy);
      if(md<MOUSE){ p.vx+=mdx/md*.012; p.vy+=mdy/md*.012; }
      p.vx*=.98; p.vy*=.98;
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<-10)p.x=W+10; else if(p.x>W+10)p.x=-10;
      if(p.y<-10)p.y=H+10; else if(p.y>H+10)p.y=-10;

      // dot
      ctx.beginPath();
      ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=dotColor;
      ctx.fill();

      // lines to neighbours
      for(let j=i+1;j<N;j++){
        const q=P[j];
        const dx=p.x-q.x, dy=p.y-q.y;
        const d=Math.sqrt(dx*dx+dy*dy);
        if(d<LINK){
          ctx.beginPath();
          ctx.moveTo(p.x,p.y); ctx.lineTo(q.x,q.y);
          ctx.strokeStyle=lineColor;
          ctx.globalAlpha=1-(d/LINK);
          ctx.lineWidth=.7;
          ctx.stroke();
          ctx.globalAlpha=1;
        }
      }

      // line to mouse
      if(md<MOUSE){
        ctx.beginPath();
        ctx.moveTo(p.x,p.y); ctx.lineTo(mouse.x,mouse.y);
        ctx.strokeStyle=mouseColor;
        ctx.globalAlpha=(1-(md/MOUSE))*.6;
        ctx.lineWidth=.8;
        ctx.stroke();
        ctx.globalAlpha=1;
      }
    }
    raf=requestAnimationFrame(draw);
  }

  init();
  draw();
})();
