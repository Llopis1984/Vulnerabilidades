// ══════════════════════════════════════════════════════════════════════════════
// CORE — File handling, launch, buildDash, charts, filters, tab switching
// ══════════════════════════════════════════════════════════════════════════════

const dz=document.getElementById('dz'),finp=document.getElementById('finp'),pf=new Map(),pfOrder=[];
['dragenter','dragover'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.add('over');}));
['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.remove('over');}));
dz.addEventListener('drop',ev=>[...ev.dataTransfer.files].forEach(hf));
finp.addEventListener('change',ev=>{[...ev.target.files].forEach(hf);finp.value='';});

// ── KEV JSON file handler ─────────────────────────────────────────────────────
window._kevJsonData = null;
document.getElementById('kevFile').addEventListener('change', function(ev){
  var file = ev.target.files[0]; if(!file) return;
  var rd = new FileReader();
  rd.onload = function(e){
    try {
      var data = JSON.parse(e.target.result);
      if(!data.vulnerabilities || !Array.isArray(data.vulnerabilities)) throw new Error('Formato incorrecto');
      window._kevJsonData = data;
      _kevUISuccess(data);
      console.log('[KEV] JSON cargado localmente:', data.vulnerabilities.length, 'entradas');
      // Si ya hay dashboard cargado, recalcular
      if(window._raw && window._raw.length > 0){
        var cveSet = new Set();
        window._raw.forEach(function(r){ (r.cves||'').split('|').forEach(function(c){ c=c.trim(); if(/^CVE-/i.test(c)) cveSet.add(c); }); });
        loadKEVFromData(data, cveSet);
        if(window.tryRenderKEV) tryRenderKEV(0);
      }
    } catch(err) {
      var er = document.getElementById('uplE'); er.textContent = 'Error leyendo KEV JSON: ' + err.message; er.style.display = 'block';
    }
    ev.target.value = '';
  };
  rd.readAsText(file, 'UTF-8');
});
document.getElementById('nBtn').addEventListener('click',reset);
document.getElementById('aBtn').addEventListener('click',function(){
  var v=parseInt(document.getElementById('totalDevInp').value);
  if(!v||v<1){document.getElementById('totalDevInp').classList.add('err');document.getElementById('totalDevInp').focus();var er=document.getElementById('uplE');er.textContent='Introduce el Nº Total de Dispositivos antes de analizar';er.style.display='block';return;}
  document.getElementById('totalDevInp').classList.remove('err');totalDevices=v;
  document.getElementById('totalDevModal').value=v;
  if(pf.size)launch();
});
document.getElementById('darkBtn').addEventListener('click',()=>{document.documentElement.classList.toggle('dark');var isDark=document.documentElement.classList.contains('dark');document.querySelector('#darkBtn .material-icons-round').textContent=isDark?'light_mode':'dark_mode';try{localStorage.setItem('dark_mode',isDark?'1':'0');}catch(e){}});
// Settings modal
var totalDevices=0;
document.getElementById('cfgBtn').addEventListener('click',function(){document.getElementById('totalDevModal').value=totalDevices||'';document.getElementById('cfgModal').classList.add('open');});
document.getElementById('cfgClose').addEventListener('click',function(){document.getElementById('cfgModal').classList.remove('open');});
document.getElementById('cfgModal').addEventListener('click',function(e){if(e.target===this)this.classList.remove('open');});
document.getElementById('cfgSave').addEventListener('click',function(){
  var v=parseInt(document.getElementById('totalDevModal').value);
  if(!v||v<1){document.getElementById('totalDevModal').classList.add('err');return;}
  document.getElementById('totalDevModal').classList.remove('err');
  totalDevices=v;document.getElementById('totalDevInp').value=v;
  document.getElementById('cfgModal').classList.remove('open');
});
// Sync inline input changes to modal
document.getElementById('totalDevInp').addEventListener('input',function(){this.classList.remove('err');document.getElementById('uplE').style.display='none';});
document.getElementById('totalDevModal').addEventListener('input',function(){this.classList.remove('err');});

// ── Worker onmessage handler (Worker created in worker.js) ──
if(_csvWorker){
  _csvWorker.onmessage = function(e){
    var d = e.data;
    if(d.rows.length < 2){
      var er=document.getElementById('uplE');er.textContent=d.fileName+': sin datos ('+d.rows.length+')';er.style.display='block';return;
    }
    pf.set(d.fileName,{name:d.fileName, rows:d.rows, sep:d.sep, _processed:true});
    if(!pfOrder.includes(d.fileName)) pfOrder.push(d.fileName);
    rfList();
  };
}

function hf(file){
  const er=document.getElementById('uplE');er.style.display='none';
  if(!file.name.match(/\.(csv|txt)$/i)){er.textContent=file.name+': solo .csv/.txt';er.style.display='block';return;}
  const rd=new FileReader();
  rd.onload=function(e){let txt=e.target.result;if(txt.includes('\ufffd')){const r2=new FileReader();r2.onload=ev=>_doParseFile(file.name,ev.target.result);r2.readAsText(file,'ISO-8859-1');return;}_doParseFile(file.name,txt);};
  rd.readAsText(file,'UTF-8');
}
function _doParseFile(fileName, txt){
  if(_csvWorker){
    _csvWorker.postMessage({fileName:fileName, text:txt});
  } else {
    procF({name:fileName}, txt);
  }
}
function procF(file,txt){
  const er=document.getElementById('uplE');const firstLine=(txt.split(/\r?\n/).find(l=>l.trim()))||'';const sep=detectSep(firstLine);
  const rows=parseCsv(txt);if(rows.length<2){er.textContent=file.name+': sin datos ('+rows.length+')';er.style.display='block';return;}
  pf.set(file.name,{name:file.name,rows,sep});if(!pfOrder.includes(file.name))pfOrder.push(file.name);rfList();
}
// parseCsv, splitQ, detectSep, fi2, g — defined in utils.js
function rfList(){document.getElementById('fl').style.display='block';document.getElementById('ffc').textContent='('+pf.size+')';
  var total=pfOrder.length;
  document.getElementById('fis').innerHTML=pfOrder.map(function(name,i){var f=pf.get(name);if(!f)return '';return '<div class="fi"><span class="pos">'+(i+1)+'</span><div class="ord"><button onclick="moveF('+i+',-1)"'+(i===0?' disabled':'')+'><span class="material-icons-round">keyboard_arrow_up</span></button><button onclick="moveF('+i+',1)"'+(i===total-1?' disabled':'')+'><span class="material-icons-round">keyboard_arrow_down</span></button></div><span class="material-icons-round">description</span><span class="fn">'+f.name+'</span><span class="fm">'+f.rows.length+' filas · sep: <strong>'+(f.sep===','?',':';')+'</strong></span><button class="rb" onclick="rmF(\''+f.name+'\')"><span class="material-icons-round">close</span></button></div>';}).join('');
  const b=document.getElementById('aBtn');b.style.display=pf.size?'block':'none';b.textContent=pf.size>1?'Analizar '+pf.size+' ficheros':'Analizar';
  document.getElementById('cfgInline').style.display=pf.size?'block':'none';}
window.moveF=function(idx,dir){var newIdx=idx+dir;if(newIdx<0||newIdx>=pfOrder.length)return;var tmp=pfOrder[idx];pfOrder[idx]=pfOrder[newIdx];pfOrder[newIdx]=tmp;rfList();};
window.rmF=function(n){pf.delete(n);var i=pfOrder.indexOf(n);if(i>=0)pfOrder.splice(i,1);rfList();if(!pf.size)document.getElementById('fl').style.display='none';};
function reset(){pf.clear();pfOrder.length=0;document.getElementById('uplScr').style.display='flex';document.getElementById('app').style.display='none';document.getElementById('nBtn').style.display='none';document.getElementById('viewTabs').style.display='none';document.getElementById('fl').style.display='none';document.getElementById('fis').innerHTML='';document.getElementById('aBtn').style.display='none';document.getElementById('cfgInline').style.display='none';document.getElementById('uplE').style.display='none';document.getElementById('upd').textContent='—';document.getElementById('ttWrap').style.display='none';finp.value='';var sw=document.getElementById('searchWrap');if(sw)sw.style.display='none';var gs=document.getElementById('globalEnvSel');if(gs)gs.style.display='none';var gts=document.getElementById('globalTowerSel');if(gts)gts.style.display='none';var cb=document.getElementById('checklistBtn');if(cb)cb.style.display='none';if(window._loadSavedSnapshots)window._loadSavedSnapshots();}
// pDate, dDiff, getEnvIcon — defined in utils.js

// Configuración del viaje en el tiempo
document.getElementById('ttSel').addEventListener('change', function(e) {
  window._currentFileIndex = parseInt(e.target.value);
  let all = pf.get(pfOrder[window._currentFileIndex]).rows;
  buildDash(all, window._snapshots, window._currentFileIndex);
});

// ── CISA KEV (global) ────────────────────────────────────────────────────────
window._kevSet    = null;
window._kevMap    = {};
window._kevJsonData = null;

// Construye _kevSet/_kevMap cruzando el catálogo con los CVEs del parque
function loadKEVFromData(jsonData, cveSet){
  window._kevSet = new Set();
  window._kevMap = {};
  var vulns = jsonData.vulnerabilities || [];
  vulns.forEach(function(v){
    if(!v.cveID) return;
    if(cveSet && cveSet.size > 0 && !cveSet.has(v.cveID)) return;
    window._kevSet.add(v.cveID);
    window._kevMap[v.cveID] = {
      vendor:     v.vendorProject || '',
      product:    v.product || '',
      vulnName:   v.vulnerabilityName || '',
      dateAdded:  v.dateAdded || '',
      dueDate:    v.dueDate || '',
      desc:       v.shortDescription || '',
      action:     v.requiredAction || '',
      ransomware: v.knownRansomwareCampaignUse || 'Unknown'
    };
  });
  window._kevStatus = {
    ok: true,
    total: window._kevSet.size,
    checked: vulns.length,
    catalogVersion: jsonData.catalogVersion || '',
    dateReleased: jsonData.dateReleased || ''
  };
  console.log('[KEV] ✅ ' + window._kevSet.size + ' matches en ' + vulns.length + ' entradas del catálogo v' + (jsonData.catalogVersion||'?'));
}

// Cache functions (_CACHE_KEYS, _CACHE_TTL, _cacheGet, _cacheSet, _cacheIsFresh,
// _fetchCached, _fetchTimeout) — defined in utils.js

// ── Pre-carga al abrir el HTML ─────────────────────────────────────────────
// Se ejecuta inmediatamente — no espera a que el usuario haga nada
async function _preloadOnOpen(){
  _kevTabLoadingIndicator('loading');
  // 1. KEV catalog
  try{
    var kevRes = await _fetchCached(
      'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
      'kev', _CACHE_TTL.kev
    );
    var kevData = JSON.parse(kevRes.data);
    window._kevJsonData = kevData;
    // Si ya hay CVEs del parque cargados, procesar; sino se procesará en launch()
    if(window._allCvesLoaded){
      loadKEVFromData(kevData, window._allCvesLoaded);
    }
    _kevTabLoadingIndicator('ready', (kevData.vulnerabilities||[]).length);
    console.log('[PRELOAD] KEV listo: '+(kevData.vulnerabilities||[]).length+' entradas'+(kevRes.fromCache?' (caché)':' (descargado)'));
  } catch(e){
    _kevTabLoadingIndicator('error');
    console.warn('[PRELOAD] KEV falló:', e.message);
  }
  // 2. EPSS data — cargar en background
  if(!_epssLoaded && !_epssLoading){
    _epssLoading = true;
    try{
      var epssRes = await _fetchCached(
        'https://raw.githubusercontent.com/jgamblin/KEV_EPSS/main/epss_kev_nvd.csv',
        'epss', _CACHE_TTL.epss
      );
      // Parsear EPSS
      var epssLines = epssRes.data.split('\n');
      var epssHdr = epssLines[0].toLowerCase().split(',').map(function(h){return h.trim();});
      var iCVE=epssHdr.indexOf('cve'), iEPSS=epssHdr.indexOf('epss'),
          iPct=epssHdr.findIndex(function(h){return h.includes('percentile');}),
          iCVSS=epssHdr.indexOf('cvss3'), iDesc=epssHdr.indexOf('description'),
          iVend=epssHdr.indexOf('vendor'), iProd=epssHdr.indexOf('product');
      for(var i=1;i<epssLines.length;i++){
        var pl=epssLines[i].trim(); if(!pl) continue;
        var parts=_parseCSVLine(pl);
        var cve=parts[iCVE]||''; if(!cve.startsWith('CVE-')) continue;
        _epssData[cve]={
          cvss3:parseFloat(parts[iCVSS])||null,
          epss:parseFloat(parts[iEPSS])||null,
          epssPercentile:parseFloat(parts[iPct])||null,
          description:(parts[iDesc]||'').replace(/^"|"$/g,'').trim(),
          vendor:parts[iVend]||'', product:parts[iProd]||''
        };
      }
      _epssLoaded=true;
      console.log('[PRELOAD] EPSS listo: '+Object.keys(_epssData).length+' CVEs'+(epssRes.fromCache?' (caché)':' (descargado)'));
    } catch(e){
      console.warn('[PRELOAD] EPSS falló:', e.message);
    }
    _epssLoading=false;
  }
}

// Indicador visual en la pestaña KEV durante carga
function _kevTabLoadingIndicator(state, count){
  var badge = document.getElementById('kevTabBadge');
  if(!badge) return;
  if(state==='loading'){
    badge.style.display='inline';
    badge.style.background='var(--t2)';
    badge.textContent='⏳';
  } else if(state==='ready'){
    badge.style.display='inline';
    badge.style.background='var(--err)';
    badge.textContent=count||'✓';
  } else if(state==='error'){
    badge.style.display='inline';
    badge.style.background='var(--warn)';
    badge.textContent='!';
  }
}

// Arrancar precarga en cuanto el DOM está listo
document.addEventListener('DOMContentLoaded', function(){
  // Pequeño delay para no competir con la carga inicial del HTML
  setTimeout(_preloadOnOpen, 300);
});

// ── Versión mejorada de autoFetchKEV que usa la caché ─────────────────────
// Intenta descargar el catálogo desde GitHub (CORS abierto en raw.githubusercontent.com)
async function autoFetchKEV(cveSet){
  // Usar caché inteligente — si ya se precargó, reutilizar
  if(window._kevJsonData){
    loadKEVFromData(window._kevJsonData, cveSet);
    _kevUISuccess(window._kevJsonData);
    return true;
  }
  // Sino, descargar con caché
  try{
    var kevRes = await _fetchCached(
      'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
      'kev', _CACHE_TTL.kev
    );
    var data = JSON.parse(kevRes.data);
    if(!data.vulnerabilities) throw new Error('Formato inesperado');
    window._kevJsonData = data;
    loadKEVFromData(data, cveSet);
    window._kevStatus.source = 'GitHub cisagov/kev-data' + (kevRes.fromCache?' (caché)':'');
    _kevUISuccess(data);
    _kevTabLoadingIndicator('ready', data.vulnerabilities.length);
    console.log('[KEV] ✅ ' + data.vulnerabilities.length + ' entradas' + (kevRes.fromCache?' (caché)':' (descargado)'));
    return true;
  } catch(e){
    console.warn('[KEV] fetch fallido:', e.message);
    _kevTabLoadingIndicator('error');
    return false;
  }
}

function _kevUISuccess(data){
  var label = document.getElementById('kevFileLabel');
  if(label) label.innerHTML = '🛡 KEV listo &mdash; <strong>' + (data.vulnerabilities||[]).length + '</strong> entradas · v' + (data.catalogVersion||'?') + ' <span style="color:var(--ok)">✅</span>';
  var dz2 = document.getElementById('kevDropZone');
  if(dz2){
    dz2.style.borderColor = 'var(--ok)'; dz2.style.background = 'rgba(26,122,50,.06)';
    var ico = dz2.querySelector('.material-icons-round');
    if(ico){ ico.style.color='var(--ok)'; ico.textContent='verified_user'; }
  }
}

// normEnv, parseCVEs, stampKEV, bdg, gR — defined in utils.js

function launch(){
  const snapshots=[];
  const baseEnvs = ['Portatil', 'Cajero', 'Fijo', 'Virtual', 'Actualizador', 'Apple'];
  // Extraer CVEs únicos de todos los ficheros cargados y pasarlos a loadKEV
  var _allCves = new Set();
  pfOrder.forEach(function(name){
    var f = pf.get(name); if(!f) return;
    f.rows.forEach(function(r){
      (r.cves||'').split('|').forEach(function(c){ c=c.trim(); if(/^CVE-/i.test(c)) _allCves.add(c); });
    });
  });
  // Guardar CVEs para que la precarga los use si llega después del launch
  window._allCvesLoaded = _allCves;
  // KEV: intentar descarga automática desde GitHub; si ya hay datos, reusar
  if(window._kevJsonData){
    loadKEVFromData(window._kevJsonData, _allCves);
  } else {
    window._kevSet = null; window._kevStatus = null;
    autoFetchKEV(_allCves); // no bloquea
  }

  // F7-PERF: Pre-process file rows (normalize + diasQualys + parseCVEs) once per file
  pfOrder.forEach(function(name){
    var f=pf.get(name); if(!f||f._processed) return;
    f.rows.forEach(function(r){
      r.entorno = normEnv(r.entorno);
      if(r.diasQualys===undefined||r.diasQualys===0){r._fd=pDate(r.fechaEsc);r.diasQualys=dDiff(r._fd);}
      r._parsedCves = parseCVEs(r.cves);
      // Feature: Aging real — días desde primera detección
      r.diasAbierta = r.fechaDet ? dDiff(pDate(r.fechaDet)) : r.diasQualys;
      r.diasIncump = r.fechaIncump ? dDiff(pDate(r.fechaIncump)) : null;
    });
    f._processed = true;
  });

  // Torre responsable — siempre, aunque el worker ya marcase _processed=true
  pfOrder.forEach(function(name){
    var f=pf.get(name); if(!f) return;
    if(f._towersClassified) return;
    if(window._enrichRowWithTower){
      f.rows.forEach(function(r){ window._enrichRowWithTower(r); });
      f._towersClassified = true;
    }
  });

  pfOrder.forEach(name=>{
    const f=pf.get(name);if(!f)return;
    const rows=f.rows;
    const hS={};
    rows.forEach(r=>{
      let eNorm=r.entorno; // F7: already normalized above
      if(!hS[r.hostname])hS[r.hostname]={hostname:r.hostname,entorno:eNorm,estadoAD:r.estadoAD,diasLogon:r.diasLogon,diasQualys:r.diasQualys||0,vc:0};
      hS[r.hostname].vc++;
      if(r.entorno)hS[r.hostname].entorno=eNorm;
      if(r.estadoAD!=='SIN ESTADO')hS[r.hostname].estadoAD=r.estadoAD;
    });
    const hArr=Object.values(hS);

    var byEnv={};
    baseEnvs.forEach(e=>{byEnv[normEnv(e)]={totalH:0,hab:0,des:0,totalV:0};});

    hArr.forEach(function(h){
      var e=h.entorno; // F7: already normalized
      if(!byEnv[e])byEnv[e]={totalH:0,hab:0,des:0,totalV:0};
      byEnv[e].totalH++;
      if(h.estadoAD==='HABILITADO')byEnv[e].hab++;
      if(h.estadoAD==='DESHABILITADO')byEnv[e].des++;
    });
    rows.forEach(function(r){
      var e=r.entorno; // F7: already normalized
      if(byEnv[e])byEnv[e].totalV++;
    });
    snapshots.push({name:f.name,totalH:hArr.length,totalV:rows.length,hab:hArr.filter(h=>h.estadoAD==='HABILITADO').length,des:hArr.filter(h=>h.estadoAD==='DESHABILITADO').length,sin:hArr.filter(h=>h.estadoAD==='SIN ESTADO').length,avgQ:hArr.length?Math.round(hArr.reduce((s,h)=>s+h.diasQualys,0)/hArr.length):0,crit:hArr.filter(h=>h.estadoAD==='HABILITADO'&&h.diasQualys>15&&h.diasLogon>15).length,byEnv:byEnv});
  });
  
  window._snapshots = snapshots; // Almacenamos globalmente para el Selector del Tiempo
  var ttWrap = document.getElementById('ttWrap');
  var ttSel = document.getElementById('ttSel');
  
  if(snapshots.length > 1) {
     ttWrap.style.display = 'flex';
     ttSel.innerHTML = snapshots.map((s, i) => '<option value="'+i+'">'+s.name.substring(0,25)+(s.name.length>25?'...':'')+'</option>').join('');
     window._currentFileIndex = snapshots.length - 1;
     ttSel.value = window._currentFileIndex;
  } else {
     ttWrap.style.display = 'none';
     window._currentFileIndex = 0;
  }

  let all = pf.get(pfOrder[window._currentFileIndex]).rows;
  
  document.getElementById('uplScr').style.display='none';document.getElementById('app').style.display='block';document.getElementById('nBtn').style.display='inline-flex';document.getElementById('viewTabs').style.display='flex';var _pb=document.getElementById('presBtn');if(_pb)_pb.style.display='inline-flex';
  // Show search, global env filter, checklist button
  var sw=document.getElementById('searchWrap');if(sw)sw.style.display='flex';
  var cb=document.getElementById('checklistBtn');if(cb)cb.style.display='inline-flex';
  var gSel=document.getElementById('globalEnvSel');if(gSel){gSel.style.display='inline-block';gSel.innerHTML='<option value="">Todos los entornos</option>';var _envSet=new Set();pfOrder.forEach(function(n){var f=pf.get(n);if(f)f.rows.forEach(function(r){if(r.entorno)_envSet.add(r.entorno);});});[..._envSet].sort().forEach(function(e){gSel.innerHTML+='<option value="'+e+'">'+e+'</option>';});}
  var gtSel=document.getElementById('globalTowerSel');if(gtSel){gtSel.style.display='inline-block';gtSel.innerHTML='<option value="">Todas las torres</option>';var _towerSet=new Set();pfOrder.forEach(function(n){var f=pf.get(n);if(f)f.rows.forEach(function(r){if(r.torre)_towerSet.add(r.torre);});});[..._towerSet].sort().forEach(function(t){gtSel.innerHTML+='<option value="'+t+'">'+t+'</option>';});}
  // Auto-save to IndexedDB
  pfOrder.forEach(function(n){if(window._autoSaveSnapshot){var f=pf.get(n);if(f)window._autoSaveSnapshot(n,f.rows);}});
  buildDash(all, snapshots, window._currentFileIndex);
  setTimeout(function(){ if(window._updateSidebarBadges) window._updateSidebarBadges(); }, 500);
}
document.querySelectorAll('.view-tab').forEach(function(tab){
  tab.addEventListener('click',function(){
    document.querySelectorAll('.view-tab').forEach(function(t){t.classList.remove('active');});
    tab.classList.add('active');
    document.querySelectorAll('.view-panel').forEach(function(p){p.classList.remove('active');});
    var t=document.getElementById('view-'+tab.dataset.view);
    if(t) t.classList.add('active');

    // Ocultar TODOS los paneles extra
    var allExtra=['ct-kev','ct-inf','ct-sccm','ct-analysis','ct-agent','ct-towers'];
    allExtra.forEach(function(id){var el=document.getElementById(id);if(el)el.style.display='none';});

    // Dashboard (#app) — solo visible en la pestaña Dashboard y Análisis
    var appEl=document.getElementById('app');
    var isDash = tab.dataset.view==='dashboard' || tab.dataset.view==='analysis';
    if(appEl) appEl.style.display = isDash ? 'block' : 'none';
    // Analysis mode: hide shared content (data table, filters), show only analysis charts
    if(appEl){ if(tab.dataset.view==='analysis') appEl.classList.add('analysis-mode'); else appEl.classList.remove('analysis-mode'); }

    // Activar panel específico
    if(tab.dataset.view==='analysis'){
      if(window._flushDirtyCharts)window._flushDirtyCharts();
      if(window._drawTreemap){setTimeout(function(){window._drawTreemap(window._raw);},50);}
      // Show strategic panel above
      var ctA=document.getElementById('ct-analysis');
      if(!ctA){ctA=document.createElement('div');ctA.id='ct-analysis';ctA.className='ct';ctA.style.display='none';var appEl2=document.getElementById('app');if(appEl2)appEl2.parentNode.insertBefore(ctA,appEl2);}
      ctA.style.display='block';
      if(window.renderAnalysisStrategic)window.renderAnalysisStrategic();
    }
    if(tab.dataset.view==='kev'){        _showExtraPanel('ct-kev',  window.renderKEVPanel);  }
    if(tab.dataset.view==='sccm'){       _showExtraPanel('ct-sccm', window.renderSCCMPanel); }
    if(tab.dataset.view==='informe'){    _showExtraPanel('ct-inf',  window.renderInfPanel);  }
    if(tab.dataset.view==='agent'){      _showExtraPanel('ct-agent',window.renderAgentPanel);}
    if(tab.dataset.view==='towers'){     _showExtraPanel('ct-towers',window.renderTowersPanel);}
  });
});
function _showExtraPanel(id, renderFn){
  var ct=document.getElementById(id);
  if(!ct){
    ct=document.createElement('div');
    ct.id=id;
    ct.className='ct';          // misma clase que #app → max-width + padding + centering
    ct.style.display='none';    // sobreescribir display:none de .ct hasta que se active
    var appEl=document.getElementById('app');
    if(appEl) appEl.parentNode.insertBefore(ct, appEl.nextSibling);
  }
  ct.style.display='block';
  if(renderFn) renderFn();
}
document.getElementById('modalClose').addEventListener('click',()=>document.getElementById('hostModal').classList.remove('open'));

// Sidebar alert badges
window._updateSidebarBadges = function(){
  var raw = window._raw; if(!raw) return;
  // KEV badge — pulse if there are KEV vulns
  var kevBadge = document.getElementById('kevSidebarBadge');
  if(kevBadge){
    var hasKEV = raw.some(function(r){ return r.isKEV; });
    kevBadge.classList.toggle('visible', hasKEV);
  }
  // Agent badge — pulse if SLA breached (>5% devices vulnerable)
  var agentBadge = document.getElementById('agentSidebarBadge');
  if(agentBadge){
    var hosts = {}; raw.forEach(function(r){ if(r.hostname) hosts[r.hostname]=1; });
    var total = window.totalDevices || 0;
    var pct = total>0 ? Object.keys(hosts).length/total : 0;
    agentBadge.classList.toggle('visible', pct >= 0.05);
    agentBadge.classList.toggle('pulse', pct >= 0.05);
  }
};

// Generic info popover
window._showInfoPop=function(btn, title, rows, legend){
  var existing=document.getElementById('riskInfoPop');
  if(existing){existing.remove();return;}
  var r=btn.getBoundingClientRect();
  var pop=document.createElement('div');
  pop.id='riskInfoPop';
  var left=Math.min(Math.max(r.left-100,12),window.innerWidth-310);
  var top=r.bottom+8;
  if(top+300>window.innerHeight) top=r.top-310;
  pop.style.cssText='position:fixed;top:'+top+'px;left:'+left+'px;background:var(--s1);border:1px solid var(--olv);border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.18);padding:16px 18px;width:300px;z-index:1000;font-family:var(--fb);font-size:.72rem;color:var(--t);line-height:1.6;animation:fadeScale .2s ease';
  var html='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><div style="font-family:var(--fd);font-weight:700;font-size:.82rem;color:var(--p)">'+title+'</div><span class="material-icons-round" style="font-size:16px;color:var(--t2);cursor:pointer" onclick="this.parentElement.parentElement.remove()">close</span></div>';
  html+='<div style="display:flex;flex-direction:column;gap:7px">';
  rows.forEach(function(row){
    html+='<div style="display:flex;justify-content:space-between;gap:8px"><span>'+row[0]+'</span><strong style="color:'+(row[2]||'var(--t)')+'">'+row[1]+'</strong></div>';
  });
  html+='</div>';
  if(legend) html+='<div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--olv);font-size:.65rem;color:var(--t2)">'+legend+'</div>';
  pop.innerHTML=html;
  document.body.appendChild(pop);
  setTimeout(function(){document.addEventListener('click',function _cl(e){if(!pop.contains(e.target)&&e.target!==btn){pop.remove();document.removeEventListener('click',_cl);}});},10);
};
// Shortcut for env risk info
window._showRiskInfo=function(btn){
  window._showInfoPop(btn,'Índice de Riesgo por Entorno (0-100)',[
    ['Severidad crítica (VPR 9.0+)','25pts','var(--err)'],
    ['Hosts críticos (Q+AD >15d)','20pts','var(--err)'],
    ['CISA KEV activos','20pts','var(--warn)'],
    ['Antigüedad media (60d=máx)','15pts'],
    ['Densidad vulns/host (15+=máx)','10pts'],
    ['Equipos fantasma (%)','10pts']
  ],'<span style="color:var(--ok)">■</span> 0-39 Bajo &nbsp;<span style="color:var(--warn)">■</span> 40-69 Medio &nbsp;<span style="color:var(--err)">■</span> 70+ Alto');
};
document.getElementById('hostModal').addEventListener('click',e=>{if(e.target===e.currentTarget)e.currentTarget.classList.remove('open');});
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.getElementById('hostModal').classList.remove('open');});

window.openDiffModal=function(tipo){
  var list = window._diffH[tipo];
  var isNew = tipo === 'nuevos';
  var title = isNew ? 'Nuevos Equipos Afectados' : 'Equipos Resueltos (Limpios)';
  var desc = isNew ? 'Aparecen en el CSV actual, pero no estaban en el primero de todos.' : 'Estaban en el primer CSV, pero ya no aparecen en el actual seleccionado.';
  var icon = isNew ? 'warning' : 'verified';
  var col = isNew ? 'var(--err)' : 'var(--ok)';
  
  document.getElementById('modalHostname').textContent = title;
  document.querySelector('#hostModal .modal-header .material-icons-round').textContent = icon;
  document.querySelector('#hostModal .modal-header .material-icons-round').style.color = col;
  
  var body = '<div style="margin-bottom:18px"><p style="font-size:.78rem;color:var(--t2);margin-bottom:14px">'+desc+'</p><h3 style="font-family:var(--fd);font-size:.85rem;font-weight:500;margin-bottom:10px;display:flex;align-items:center;gap:6px;color:'+col+'"><span class="material-icons-round" style="font-size:16px">dns</span> Total: '+list.length+' equipos</h3>';
  
  if(list.length>0){
    body+='<ul class="modal-vuln-list" style="max-height:400px;overflow-y:auto;border:1px solid var(--olv);border-radius:8px">';
    list.forEach(function(h){
       var clk = isNew ? 'onclick="openHostModal(\''+h+'\')"' : '';
       var hov = isNew ? 'onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'" style="cursor:pointer;transition:background .15s"' : '';
       var lnk = isNew ? '<span class="material-icons-round" style="font-size:14px;color:var(--t2);opacity:.5">open_in_new</span>' : '';
       
       body+='<li '+hov+' '+clk+'><span class="material-icons-round" style="color:'+col+'">dns</span><span style="flex:1;font-weight:500;margin-left:4px">'+h+'</span>'+lnk+'</li>';
    });
    body+='</ul>';
  }else{
    body+='<p style="color:var(--t2);font-size:.8rem;padding:20px 0;text-align:center;background:var(--s2);border-radius:8px">No hay equipos en esta categoría.</p>';
  }
  body+='</div>';
  
  document.getElementById('modalBody').innerHTML=body;
  document.getElementById('hostModal').classList.add('open');
  if(window.hideGlobalTip) hideGlobalTip();
};

function buildDash(raw,snapshots, fIndex){
  if(fIndex === undefined) fIndex = snapshots.length - 1; // Fallback
  
  const NOW=new Date();NOW.setHours(0,0,0,0);
  document.getElementById('upd').textContent=NOW.toLocaleDateString('es-ES');
  window._raw=raw; window._drawTreemap=null;
  
  // F7-PERF: rows are already normalized (entorno, diasQualys, _parsedCves) in launch()
  // Stamp KEV flags using pre-parsed CVE lists
  window.stampKEV();
  
  const hm={};
  raw.forEach(r=>{
     if(!hm[r.hostname])hm[r.hostname]={hostname:r.hostname,entorno:r.entorno,torre:r.torre||'Sin clasificar',fechaEsc:r.fechaEsc,diasQualys:r.diasQualys,estadoAD:r.estadoAD,diasLogon:r.diasLogon,vc:0,vulns:[],diasAbierta:r.diasAbierta||0};
     const h=hm[r.hostname];
     h.vc++;
     h.vulns.push(r.vulnName);
     if(r.diasQualys<h.diasQualys){h.diasQualys=r.diasQualys;h.fechaEsc=r.fechaEsc;}
     if((r.diasAbierta||0)>h.diasAbierta) h.diasAbierta=r.diasAbierta;
     if(r.estadoAD!=='SIN ESTADO')h.estadoAD=r.estadoAD;
     if(r.diasLogon>0)h.diasLogon=r.diasLogon;
     if(r.entorno)h.entorno=r.entorno;
     if(r.torre && (!h.torre||h.torre==='Sin clasificar')) h.torre = r.torre;
  });
  const hosts=Object.values(hm),tH=hosts.length,tV=raw.length;
  const hab=hosts.filter(h=>h.estadoAD==='HABILITADO'),des=hosts.filter(h=>h.estadoAD==='DESHABILITADO'),sin=hosts.filter(h=>h.estadoAD==='SIN ESTADO');

  // ===== MODAL DE HOST =====
  window.openHostModal=function(hostname){
    var h=hm[hostname];
    if(!h){var k=Object.keys(hm).find(function(k){return k.toLowerCase()===hostname.toLowerCase();});if(k)h=hm[k];else return;}
    document.getElementById('modalHostname').textContent=h.hostname;
    document.querySelector('#hostModal .modal-header .material-icons-round').textContent='dns';
    document.querySelector('#hostModal .modal-header .material-icons-round').style.color='var(--p)';
    var eb=h.estadoAD==='HABILITADO'?'bok':h.estadoAD==='DESHABILITADO'?'ber':'bof';
    var qb=h.diasQualys>15?'ber':h.diasQualys>7?'bwa':'bok';
    var ab=h.diasLogon>15?'ber':h.diasLogon>7?'bwa':'bok';
    var rv=h.estadoAD==='HABILITADO'&&h.diasQualys>15&&h.diasLogon>15?'critico':h.diasQualys>15||h.diasLogon>15?'atencion':'ok';
    var rk=rv==='critico'?'<span class="bd ber">&#9888; CRÍTICO</span>':rv==='atencion'?'<span class="bd bwa">ATENCIÓN</span>':'<span class="bd bok">OK</span>';
    var body='<div class="modal-kpi">'
      +'<div class="modal-kpi-item"><div class="mkv">'+h.entorno+'</div><div class="mkl">Entorno</div></div>'
      +'<div class="modal-kpi-item"><div class="mkv"><span class="bd '+eb+'">'+h.estadoAD+'</span></div><div class="mkl">Estado AD</div></div>'
      +'<div class="modal-kpi-item"><div class="mkv"><span class="bd '+qb+'">'+h.diasQualys+'d</span></div><div class="mkl">Días Qualys</div></div>'
      +'<div class="modal-kpi-item"><div class="mkv"><span class="bd '+(h.diasAbierta>30?'ber':h.diasAbierta>15?'bwa':'bok')+'">'+h.diasAbierta+'d</span></div><div class="mkl">Días Abierta</div></div>'
      +'<div class="modal-kpi-item"><div class="mkv"><span class="bd '+ab+'">'+h.diasLogon+'d</span></div><div class="mkl">Días Logon AD</div></div>'
      +'<div class="modal-kpi-item"><div class="mkv">'+h.vc+'</div><div class="mkl">Vulnerabilidades</div></div>'
      +'<div class="modal-kpi-item"><div class="mkv">'+rk+'</div><div class="mkl">Riesgo</div></div>'
      +'</div>';
    var hVulns=raw.filter(function(r){return r.hostname===h.hostname;});
    if(hVulns.length){
      body+='<h3 style="font-family:var(--fd);font-size:.85rem;font-weight:500;margin:16px 0 8px;display:flex;align-items:center;gap:6px;color:var(--p)"><span class="material-icons-round" style="font-size:16px">bug_report</span> Vulnerabilidades ('+hVulns.length+')</h3>';
      body+='<ul class="modal-vuln-list" style="max-height:320px;overflow-y:auto">';
      hVulns.forEach(function(r){
        var vpr=r.nivelVPR?'<span class="bd bwa" style="margin-left:4px;flex-shrink:0">VPR '+r.nivelVPR+'</span>':'';
        body+='<li><span class="material-icons-round" style="color:var(--warn);flex-shrink:0">warning_amber</span><span style="flex:1;font-size:.78rem">'+r.vulnName+'</span>'+vpr+'</li>';
      });
      body+='</ul>';
    }
    document.getElementById('modalBody').innerHTML=body;
    document.getElementById('hostModal').classList.add('open');
    if(window.hideGlobalTip)hideGlobalTip();
  };
  
  // F7-PERF: entorno already normalized in launch(), isKEV already stamped
  // Construir mapa de entornos — solo entornos con datos reales
  const entC={};
  hosts.forEach(h=>{const e=h.entorno;entC[e]=(entC[e]||0)+1;});
  Object.keys(entC).forEach(function(k){if(entC[k]===0&&Object.keys(entC).some(function(k2){return k2!==k&&normEnv(k2)===normEnv(k)&&entC[k2]>0;}))delete entC[k];});
  const ents=Object.entries(entC).sort((a,b)=>b[1]-a[1]);

  const vc={};raw.forEach(function(r){
    if(!r.vulnName) return;
    var cveList=r._parsedCves||parseCVEs(r.cves); // F7: use pre-parsed
    if(!vc[r.vulnName]) vc[r.vulnName]={count:0,hosts:new Set(),ents:new Set(),vpr:r.nivelVPR,sol:r.solucion,cves:new Set(),kevCves:new Set(),fechaPub:r.fechaPub};
    vc[r.vulnName].count++;
    vc[r.vulnName].hosts.add(r.hostname);
    vc[r.vulnName].ents.add(r.entorno);
    cveList.forEach(function(c){ vc[r.vulnName].cves.add(c); if(window._kevSet && window._kevSet.has(c)) vc[r.vulnName].kevCves.add(c); });
  });
  const topV=Object.entries(vc).sort((a,b)=>b[1].hosts.size-a[1].hosts.size).slice(0,10);
  const s7=hosts.filter(h=>h.diasQualys<=7).length,s30=hosts.filter(h=>h.diasQualys<=30).length,s90=hosts.filter(h=>h.diasQualys<=90).length,nS=hosts.filter(h=>h.diasQualys>90).length;
  const noScanHosts=hosts.filter(h=>h.diasQualys>=999).length;
  const maxQ=Math.max(...hosts.map(h=>h.diasQualys).filter(d=>d<999),30),maxAD=Math.max(...hosts.map(h=>h.diasLogon),30);
  const maxQSlider=noScanHosts>0?999:maxQ;
  function tk(vals,mn,mx){return vals.map(v=>'<span style="left:'+((v-mn)/(mx-mn)*100)+'%">'+v+'</span>').join('');}

  // Evolution HTML
  let evoHTML='';
  if(snapshots.length>1){
    window._snapshots=snapshots;
    var first=snapshots[0], last=snapshots[fIndex]; // Ahora compara el primero con el seleccionado en la máquina del tiempo
    
    // LÓGICA DE DELTAS (Diferencias reales entre Primer CSV y Seleccionado CSV)
    var hFirst = new Set(pf.get(pfOrder[0]).rows.map(r=>r.hostname));
    var hLast = new Set(pf.get(pfOrder[fIndex]).rows.map(r=>r.hostname));
    var hNuevos = [...hLast].filter(x => !hFirst.has(x)).sort();
    var hResueltos = [...hFirst].filter(x => !hLast.has(x)).sort();
    window._diffH = { nuevos: hNuevos, resueltos: hResueltos };

    // 4 KPI cards: Vulnerabilidades, Equipos, Habilitados, Deshabilitados
    evoHTML='<div class="st ai d2"><span class="material-icons-round">trending_up</span> Evolución ('+snapshots.length+' snapshots totales)</div>';
    evoHTML+='<div class="evo-wrap ai d2"><h3><span class="material-icons-round" style="font-size:16px;color:var(--p)">compare_arrows</span> Primer fichero vs Fecha Seleccionada</h3>';
    evoHTML+='<div class="evo-summary">';
    var sumMetrics=[{k:'totalH',l:'Equipos con Vulns',inv:true},{k:'totalV',l:'Vulnerabilidades',inv:true},{k:'hab',l:'Habilitados',inv:false},{k:'des',l:'Deshabilitados',inv:true}];
    sumMetrics.forEach(function(m){
      var f=first[m.k],l2=last[m.k],d=l2-f;
      var dcls=d===0?'evo-flat':((m.inv&&d>0)||(!m.inv&&d<0))?'evo-up':'evo-down';
      evoHTML+='<div class="evo-sum-card"><div class="el">'+m.l+'</div><div class="ev">'+l2+'</div><div class="evo-delta '+dcls+'">'+(d>0?'+':'')+d+'</div></div>';
    });
    
    // Tarjetas Delta Interactivos
    evoHTML+='<div class="evo-sum-card" style="border:1px solid var(--err);cursor:pointer;background:var(--errc);transition:transform 0.15s" onmouseover="this.style.transform=\'scale(1.03)\'" onmouseout="this.style.transform=\'scale(1)\'" onclick="openDiffModal(\'nuevos\')"><div class="el" style="color:var(--err);font-weight:700">Nuevos Equipos ⚠️</div><div class="ev" style="color:var(--err)">'+hNuevos.length+'</div><div class="evo-delta evo-up" style="font-size:0.65rem;background:transparent;padding:0;color:var(--err)">+ Clic para ver</div></div>';
    
    evoHTML+='<div class="evo-sum-card" style="border:1px solid var(--ok);cursor:pointer;background:var(--okc);transition:transform 0.15s" onmouseover="this.style.transform=\'scale(1.03)\'" onmouseout="this.style.transform=\'scale(1)\'" onclick="openDiffModal(\'resueltos\')"><div class="el" style="color:var(--ok);font-weight:700">Equipos Resueltos ✅</div><div class="ev" style="color:var(--ok)">'+hResueltos.length+'</div><div class="evo-delta evo-down" style="font-size:0.65rem;background:transparent;padding:0;color:var(--ok)">+ Clic para ver</div></div>';

    evoHTML+='</div>';
    
    // Metric selector tabs
    evoHTML+='<div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap"><div style="font-size:.7rem;color:var(--t2);font-weight:500;align-self:center;margin-right:4px">Gráfica temporal de:</div>';
    sumMetrics.forEach(function(m,i){
      evoHTML+='<button class="evo-mbtn'+(i===0?' active':'')+'" data-metric="'+m.k+'" data-label="'+m.l+'">'+m.l+'</button>';
    });
    evoHTML+='</div>';
    // Chart container
    evoHTML+='<div id="evoChartArea"></div></div>';
  }

  const app=document.getElementById('app');
  var tD=totalDevices,noScan=Math.max(0,tD-tH);

  app.innerHTML=
  '<div class="view-panel active" id="view-dashboard">'+
    '<div class="st ai"><svg class="dxc-ico lg" style="color:var(--p)"><use href="#dxc-globe-cyber"/></svg> Resumen del fichero — <span style="color:var(--t);font-weight:700;background:var(--s2);padding:2px 8px;border-radius:10px;margin-left:4px">'+snapshots[fIndex].name+'</span></div>'+
    '<div class="kr"><div class="kc ai d1"><div class="kl">Parque Total</div><div class="kv">'+tD+'</div><div class="ks">Dispositivos gestionados</div></div><div class="kc er ai d1"><div class="kl">Con Vulnerabilidades</div><div class="kv">'+tH+'</div><div class="ks">'+(tH/tD*100).toFixed(1)+'% del parque</div></div><div class="kc ai d1"><div class="kl">Vulnerabilidades</div><div class="kv">'+tV+'</div><div class="ks">'+(tV/tH).toFixed(1)+' vulns/equipo</div></div><div class="kc ok ai d2"><div class="kl">Habilitados</div><div class="kv">'+hab.length+'</div><div class="ks">'+(hab.length/tH*100).toFixed(1)+'% de afectados</div></div><div class="kc er ai d2"><div class="kl">Deshabilitados</div><div class="kv">'+des.length+'</div></div><div class="kc ok ai d3"><div class="kl">Sin Vulnerabilidades</div><div class="kv">'+noScan+'</div><div class="ks">'+(noScan/tD*100).toFixed(1)+'% del parque limpio</div></div></div><div class=\"kc kev ai d3\" id=\"kevKPI\" style=\"border-left-color:#7c3aed\"><div class=\"kl\" style=\"color:#7c3aed\">🛡 CISA KEV</div><div class=\"kv\" id=\"kevKPIval\" style=\"color:#7c3aed;font-size:.9rem\"><span class=\"kev-loading\"><span class=\"spinner-sm\"></span>cargando…</span></div><div class=\"ks\" id=\"kevKPIsub\"></div></div></div>'+ '<div id=\"zdBanner\"></div>'+
    '<div class="st ai d2"><span class="material-icons-round">summarize</span> Resumen Ejecutivo por Entorno <span class="material-icons-round" style="font-size:16px;color:var(--p);cursor:pointer;margin-left:4px" onclick="window._showRiskInfo(this)" id="riskInfoBtn">info_outline</span></div><div class="env-grid ai d2" id="envGrid"></div>'+
    evoHTML+
    '<div class="st ai d3"><span class="material-icons-round">analytics</span> Cumplimiento</div><div id="cKPI" class="kr"></div><div id="cAlert"></div>'+
    '<div class="st ai d4"><svg class="dxc-ico lg" style="color:var(--p)"><use href="#dxc-globe-routes"/></svg> Exposición del Parque</div><div class="cov-wrap ai d4"><h3><span class="material-icons-round" style="font-size:16px;color:var(--p)">shield</span> '+tH+' de '+tD+' equipos tienen vulnerabilidades ('+(tH/tD*100).toFixed(1)+'%)</h3><div class="cov-bar-outer"><div class="cov-bar-inner" style="width:'+(tH/tD*100).toFixed(0)+'%;background:linear-gradient(90deg,#D14600,#FF7E51)">'+(tH/tD*100).toFixed(0)+'%</div></div><div style="font-size:.72rem;color:var(--t2);margin-top:8px">De los <strong>'+tH+'</strong> equipos con vulnerabilidades:</div><div class="cov-segments"><div class="cov-seg"><div class="cov-dot" style="background:var(--ok)"></div> Escaneo ≤7d: <strong>'+s7+'</strong></div><div class="cov-seg"><div class="cov-dot" style="background:#2a9d48"></div> ≤30d: <strong>'+s30+'</strong></div><div class="cov-seg"><div class="cov-dot" style="background:var(--warn)"></div> ≤90d: <strong>'+s90+'</strong></div><div class="cov-seg"><div class="cov-dot" style="background:var(--err)"></div> >90d: <strong>'+nS+'</strong></div></div></div>'+
    '<div class="st ai d4"><span class="material-icons-round">bug_report</span> TOP 10 Vulnerabilidades <span style="font-size:.72rem;font-weight:400;color:var(--t2);margin-left:4px">(clic para expandir)</span></div><div class="vr ai d5" id="topVulns"></div>'+
    '<div class="st ai d4"><span class="material-icons-round">pie_chart</span> Distribución</div><div class="cr ai d5"><div class="cc"><h3>Estado AD</h3><div class="donut-wrap" id="dEst"></div></div><div class="cc"><h3>Cumplimiento</h3><div class="donut-wrap" id="dCum"></div></div></div>'+
  '</div>'+
  '<div class="view-panel" id="view-analysis">'+
    '<div class="st ai"><span class="material-icons-round">grid_view</span> Treemap de Vulnerabilidades (tamaño = hosts afectados)</div><div class="cc ai d1" id="treemapArea" style="margin-bottom:8px;padding:18px"></div>'+
    '<div class="cr ai d1">'+
      '<div style="flex:1;min-width:0"><div class="st ai d2"><span class="material-icons-round">bubble_chart</span> Impacto de Vulnerabilidades</div><div class="cc ai d2" id="bubbleArea"></div></div>'+
      '<div style="flex:1;min-width:0"><div class="st ai d2"><span class="material-icons-round">scatter_plot</span> Cuadrante de Riesgo (Días Q × Días AD)</div><div class="quad-wrap ai d2" id="quadArea"></div></div>'+
    '</div>'+
    '<div class="cr ai d3">'+
      '<div style="flex:1;min-width:0"><div class="st ai d3"><span class="material-icons-round">leaderboard</span> Top 10 Hosts más Vulnerables</div><div class="toph-wrap ai d3" id="tophArea"></div></div>'+
      '<div style="flex:1;min-width:0"><div class="st ai d3"><svg class="dxc-ico lg" style="color:var(--warn)"><use href="#dxc-ghost"/></svg> Equipos Fantasma</div><div class="ghost-wrap ai d3" id="ghostArea"></div></div>'+
    '</div>'+
    '<div class="st ai d4"><span class="material-icons-round">event_busy</span> Distribución de antigüedad (Días Qualys)</div><div class="cc ai d4" id="patchDays" style="margin-bottom:8px"></div>'+
  '</div>'+
  '<div class="st ai d5"><span class="material-icons-round">table_chart</span> Datos detallados del fichero</div>'+
  '<div class="tabs ai d5"><button class="tab active" id="tabEq">Equipos ('+tH+')</button><button class="tab" id="tabVu">Vulnerabilidades ('+tV+')</button></div>'+
  '<div class="fb ai d5"><div class="fb-h"><h3><span class="material-icons-round" style="font-size:16px;color:var(--p)">filter_list</span> Filtros <span class="acnt" id="aCnt" style="display:none">0</span></h3><div style="display:flex;gap:6px;align-items:center"><button class="cbtn" id="clBtn"><span class="material-icons-round">refresh</span> Limpiar</button><button class="ebtn" id="exBtn"><span class="material-icons-round" style="font-size:13px">download</span> CSV</button></div></div>'+
    '<div class="fg"><div class="fgr"><div class="fgl">Estado</div><div class="fgc" id="fEst"></div></div><div class="fdv"></div><div class="fgr"><div class="fgl">Riesgo</div><div class="fgc" id="fRsk"></div></div><div class="fdv"></div><div class="fgr"><div class="fgl">Entorno</div><div class="fgc" id="fEnt"></div></div></div>'+
    '<div style="border-top:1px solid var(--olv);margin-top:10px;padding-top:10px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;flex-wrap:wrap;gap:6px"><div style="display:flex;align-items:center;gap:6px"><span class="material-icons-round" style="font-size:15px;color:var(--p)">tune</span><span style="font-size:.65rem;text-transform:uppercase;letter-spacing:.4px;color:var(--t2);font-weight:500">Umbral (rango mín–máx)</span></div><div style="display:flex;align-items:center;gap:8px"><label style="display:inline-flex;align-items:center;gap:4px;cursor:pointer;font-size:.72rem;color:var(--t2)"><input type="checkbox" id="tTog" style="accent-color:var(--p);width:14px;height:14px"> Solo dentro de rango</label><div style="display:inline-flex;border:1px solid var(--ol);border-radius:12px;overflow:hidden"><button class="lb active" id="lA">Q &amp; AD</button><button class="lb" id="lO">Q ó AD</button></div></div></div>'+
      '<div class="sg"><div class="si"><div class="sh"><label>Días Qualys'+(noScanHosts>0?' <span style="font-size:.62rem;color:var(--warn)">('+noScanHosts+' sin fecha)</span>':'')+'</label><span class="sv" id="sqV">0 – '+maxQSlider+'</span></div><div class="dual-range"><div class="dual-track"></div><div class="dual-fill" id="qFill"></div><input type="range" id="sQMin" min="0" max="'+maxQSlider+'" value="0"><input type="range" id="sQMax" min="0" max="'+maxQSlider+'" value="'+maxQSlider+'"></div><div class="stt">'+tk([0,Math.round(maxQSlider*.25),Math.round(maxQSlider*.5),Math.round(maxQSlider*.75),maxQSlider],0,maxQSlider)+'</div></div>'+
        '<div class="si"><div class="sh"><label>Días Logon AD</label><span class="sv" id="saV">0 – '+maxAD+'</span></div><div class="dual-range"><div class="dual-track"></div><div class="dual-fill" id="aFill"></div><input type="range" id="sAMin" min="0" max="'+maxAD+'" value="0"><input type="range" id="sAMax" min="0" max="'+maxAD+'" value="'+maxAD+'"></div><div class="stt">'+tk([0,Math.round(maxAD*.25),Math.round(maxAD*.5),Math.round(maxAD*.75),maxAD],0,maxAD)+'</div></div></div></div>'+
    '<div class="rs" id="rSum"></div></div>'+
  '<div class="tb ai d5"><div class="sb"><span class="material-icons-round">search</span><input type="text" id="sIn" placeholder="Buscar..."></div></div>'+
  '<div id="tabEqP" class="tab-panel active"><div class="tc"><div class="tw"><table><thead><tr><th data-key="hostname">Host <span class="material-icons-round">unfold_more</span></th><th data-key="entorno">Entorno <span class="material-icons-round">unfold_more</span></th><th data-key="torre">Torre <span class="material-icons-round">unfold_more</span></th><th data-key="diasQualys">Días Q <span class="material-icons-round">unfold_more</span></th><th data-key="diasAbierta">Aging <span class="material-icons-round">unfold_more</span></th><th data-key="estadoAD">Estado <span class="material-icons-round">unfold_more</span></th><th data-key="diasLogon">Días AD <span class="material-icons-round">unfold_more</span></th><th data-key="vc">Vulns <span class="material-icons-round">unfold_more</span></th><th>Riesgo</th></tr></thead><tbody id="tBEq"></tbody></table></div><div class="pg"><span id="pIEq"></span><div class="ps" id="pBEq"></div></div></div></div>'+
  '<div id="tabVuP" class="tab-panel"><div class="tc"><div class="tw"><table><thead><tr><th data-key="vulnName" data-t="v">Vulnerabilidad <span class="material-icons-round">unfold_more</span></th><th data-key="hostname" data-t="v">Host <span class="material-icons-round">unfold_more</span></th><th data-key="entorno" data-t="v">Entorno <span class="material-icons-round">unfold_more</span></th><th data-key="torre" data-t="v">Torre <span class="material-icons-round">unfold_more</span></th><th data-key="diasQualys" data-t="v">Días Q <span class="material-icons-round">unfold_more</span></th><th data-key="diasAbierta" data-t="v">Aging <span class="material-icons-round">unfold_more</span></th><th data-key="estadoAD" data-t="v">Estado <span class="material-icons-round">unfold_more</span></th><th data-key="diasLogon" data-t="v">Días AD <span class="material-icons-round">unfold_more</span></th><th>Riesgo</th><th>KEV</th></tr></thead><tbody id="tBVu"></tbody></table></div><div class="pg"><span id="pIVu"></span><div class="ps" id="pBVu"></div></div></div></div>';

  // TOP VULNS
  var tvM=topV[0]?topV[0][1].hosts.size:1;
  document.getElementById('topVulns').innerHTML=topV.map(function(e,i){
    var n=e[0],v=e[1];
    var hl=[...v.hosts].slice(0,20),el=[...v.ents].filter(Boolean),sc=(v.sol||'').replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim();
    // Recomputar KEV en render time
    var freshKevCves=new Set();
    if(window._kevSet&&window._kevSet.size>0){[...v.cves].forEach(function(c){if(window._kevSet.has(c))freshKevCves.add(c);});}
    var isKEVFresh=freshKevCves.size>0;
    var kevBadge=isKEVFresh?'<span class="kev-badge"><span class="material-icons-round">shield</span>KEV</span>':'';
    var cveChips=v.cves&&v.cves.size>0?'<div style="font-size:.72rem;color:var(--t2);margin-bottom:6px;display:flex;align-items:center;flex-wrap:wrap;gap:4px"><strong>CVEs:</strong> '+[...v.cves].slice(0,8).map(function(c){var isK=freshKevCves.has(c);return '<a href="https://nvd.nist.gov/vuln/detail/'+c+'" target="_blank" style="text-decoration:none"><span class="ki-cve" style="cursor:pointer;'+(isK?'background:rgba(124,58,237,.2);color:#7c3aed;border:1px solid #7c3aed':'')+'">'+c+(isK?' 🛡':'')+'</span></a>';}).join('')+(v.cves.size>8?'<span class="bd bof">+'+( v.cves.size-8)+' más</span>':'')+'</div>':'';
    var actionBtns='<div style="display:flex;gap:6px;flex-wrap:wrap;margin:8px 0;padding-top:8px;border-top:1px solid var(--olv)">'
      +'<button class="rfbtn" style="font-size:.68rem;padding:4px 10px" onclick="event.stopPropagation();var t=document.querySelector(\'[data-view=sccm]\');if(t)t.click()"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">dynamic_feed</span> SCCM</button>'
      +'</div>';
    return '<div class="vr-r" style="'+(isKEVFresh?'border-left:3px solid #7c3aed;':'')+'" onclick="this.classList.toggle(\'open\');this.nextElementSibling.classList.toggle(\'open\')"><div class="vr-p">'+(i+1)+'</div><div class="vr-n" title="'+n+'">'+n+' '+kevBadge+'</div><div class="vr-b"><div class="vr-f" style="width:'+(v.hosts.size/tvM*100)+'%"></div></div><div class="vr-c">'+v.hosts.size+' <span style="font-size:0.6rem;opacity:0.7;font-weight:500">equipos</span></div><span class="material-icons-round vr-exp">expand_more</span></div><div class="vr-detail"><div class="vd-grid"><div class="vd-item"><div class="vd-label">Equipos afectados</div><div class="vd-val">'+v.hosts.size+'</div></div><div class="vd-item"><div class="vd-label">Instancias (Filas)</div><div class="vd-val">'+v.count+'</div></div><div class="vd-item"><div class="vd-label">Nivel VPR</div><div class="vd-val">'+(v.vpr||'N/A')+'</div></div></div>'+(el.length?'<div style="font-size:.72rem;color:var(--t2);margin-bottom:6px"><strong>Entornos:</strong> '+el.map(function(x){return '<span class="bd bof" style="display:inline-flex;align-items:center;gap:4px">'+getEnvIcon(x)+x+'</span>';}).join(' ')+'</div>':'')+ cveChips+(sc?'<div style="font-size:.75rem;line-height:1.5;margin-bottom:8px;padding:8px;background:var(--s1);border-radius:6px;border-left:3px solid var(--warn)"><strong>Solución:</strong> '+sc.substring(0,300)+(sc.length>300?'...':'')+'</div>':'')+actionBtns+'<div style="font-size:.72rem;color:var(--t2);margin-bottom:4px"><strong>Hosts:</strong></div><div class="vd-hosts">'+hl.map(function(x){return '<span class="vd-host-chip" onclick="event.stopPropagation();openHostModal(\''+x+'\')">'+x+'</span>';}).join('')+(v.hosts.size>20?'<span class="bd bof">+'+( v.hosts.size-20)+' más</span>':'')+'</div></div>';}).join('');

  // ===== 5 ANALYSIS CHARTS =====
  var globalTip=document.createElement('div');
  globalTip.className='donut-tip';
  document.body.appendChild(globalTip);

  var _tipRAF=null, _tipW=0, _tipH=0;

  function showGlobalTip(ev,html){
    cancelHideGlobalTip();
    globalTip.innerHTML=html;
    globalTip.classList.add('show');
    requestAnimationFrame(function(){
      _tipW=globalTip.offsetWidth;
      _tipH=globalTip.offsetHeight;
      _moveTip(ev.clientX, ev.clientY);
    });
  }

  function _moveTip(cx, cy){
    var tx=cx+14, ty=cy-_tipH/2-4;
    if(tx+_tipW > window.innerWidth-10) tx=cx-_tipW-14;
    if(ty+_tipH > window.innerHeight-10) ty=window.innerHeight-_tipH-10;
    if(ty<10) ty=10;
    globalTip.style.left=Math.max(10,tx)+'px';
    globalTip.style.top=ty+'px';
  }

  function posGlobalTip(ev){
    if(_tipRAF) cancelAnimationFrame(_tipRAF);
    _tipRAF=requestAnimationFrame(function(){ _moveTip(ev.clientX, ev.clientY); _tipRAF=null; });
  }

  // Versión para SVG: posiciona junto al elemento, sin seguir el cursor
  function posGlobalTipAtEl(el){
    var r=el.getBoundingClientRect();
    requestAnimationFrame(function(){
      _tipW=globalTip.offsetWidth;
      _tipH=globalTip.offsetHeight;
      var tx=r.right+8, ty=r.top-_tipH/2+r.height/2;
      if(tx+_tipW > window.innerWidth-10) tx=r.left-_tipW-8;
      if(ty+_tipH > window.innerHeight-10) ty=window.innerHeight-_tipH-10;
      if(ty<10) ty=10;
      globalTip.style.left=Math.max(10,tx)+'px';
      globalTip.style.top=ty+'px';
    });
  }

  var _tipHideTimer=null;
  function hideGlobalTip(){
    if(_tipRAF){ cancelAnimationFrame(_tipRAF); _tipRAF=null; }
    _tipHideTimer=setTimeout(function(){ globalTip.classList.remove('show'); },120);
  }
  function cancelHideGlobalTip(){
    if(_tipHideTimer){ clearTimeout(_tipHideTimer); _tipHideTimer=null; }
  }


  // 3. TREEMAP — proper 2D layout with rows
  function drawTreemap(filteredRaw){
    var el=document.getElementById('treemapArea');if(!el)return;
    var vcT={};filteredRaw.forEach(function(r){if(!r.vulnName)return;if(!vcT[r.vulnName])vcT[r.vulnName]={hosts:new Set(),count:0,vpr:r.nivelVPR};vcT[r.vulnName].hosts.add(r.hostname);vcT[r.vulnName].count++;});
    var items=Object.entries(vcT).sort(function(a,b){return b[1].hosts.size-a[1].hosts.size;}).slice(0,18).map(function(e){return{name:e[0],val:e[1].hosts.size,inst:e[1].count,vpr:e[1].vpr||'N/A'};});
    if(!items.length){el.innerHTML='<p style="color:var(--t2);font-size:.8rem">Sin datos</p>';return;}
    var W=900,H=320,pad=3;
    var totalVal=items.reduce(function(s,i){return s+i.val;},0);
    var colors=['#004AAC','#4995FF','#FFAE41','#FF7E51','#D14600','#FFC982','#A1E6FF','#1a7a32','#004AAC','#4995FF','#FFAE41','#FF7E51','#D14600','#FFC982','#A1E6FF','#1a7a32','#004AAC','#4995FF'];
    // Slice-and-dice with row grouping
    var rects=[];
    function layout(items2,x,y,w,h,depth){
      if(!items2.length)return;
      if(items2.length===1){rects.push({item:items2[0],x:x,y:y,w:w,h:h});return;}
      var tot=items2.reduce(function(s,i){return s+i.val;},0);
      var horiz=w>=h;
      var half=0,split=0;
      for(var i=0;i<items2.length;i++){half+=items2[i].val;if(half>=tot/2){split=i+1;break;}}
      if(split<1)split=1;if(split>=items2.length)split=items2.length-1;
      var leftVal=items2.slice(0,split).reduce(function(s,i){return s+i.val;},0);
      var frac=leftVal/tot;
      if(horiz){
        layout(items2.slice(0,split),x,y,w*frac,h,depth+1);
        layout(items2.slice(split),x+w*frac,y,w*(1-frac),h,depth+1);
      }else{
        layout(items2.slice(0,split),x,y,w,h*frac,depth+1);
        layout(items2.slice(split),x,y+h*frac,w,h*(1-frac),depth+1);
      }
    }
    layout(items,0,0,W,H,0);
    var s='<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;height:auto;display:block;border-radius:8px;overflow:hidden">';
    rects.forEach(function(r,i){
      var col=colors[i%colors.length];
      var rw=Math.max(r.w-pad,1),rh=Math.max(r.h-pad,1);
      s+='<rect class="tm-rect" data-idx="'+i+'" x="'+(r.x+pad/2).toFixed(1)+'" y="'+(r.y+pad/2).toFixed(1)+'" width="'+rw.toFixed(1)+'" height="'+rh.toFixed(1)+'" rx="4" fill="'+col+'" data-n="'+r.item.name.replace(/"/g,'&quot;')+'" data-h="'+r.item.val+'" data-i="'+r.item.inst+'" data-v="'+r.item.vpr+'"/>';
      if(rw>70&&rh>34){
        var mc=Math.floor(rw/7);var lb=r.item.name.length>mc?r.item.name.substring(0,mc-1)+'…':r.item.name;
        s+='<text x="'+(r.x+pad/2+8).toFixed(1)+'" y="'+(r.y+pad/2+16).toFixed(1)+'" fill="#fff" font-size="11" font-weight="600" font-family="var(--fd)" pointer-events="none">'+lb.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</text>';
        if(rh>48) s+='<text x="'+(r.x+pad/2+8).toFixed(1)+'" y="'+(r.y+pad/2+32).toFixed(1)+'" fill="rgba(255,255,255,.7)" font-size="10" font-family="var(--fd)" pointer-events="none">'+r.item.val+' hosts</text>';
      }else if(rw>28&&rh>18){
        s+='<text x="'+(r.x+r.w/2).toFixed(1)+'" y="'+(r.y+r.h/2+4).toFixed(1)+'" text-anchor="middle" fill="#fff" font-size="9" font-weight="700" font-family="var(--fd)" pointer-events="none">'+r.item.val+'</text>';
      }
    });
    s+='</svg>';
    el.innerHTML=s;
    el.querySelectorAll('.tm-rect').forEach(function(rect){
      rect.addEventListener('mouseenter',function(ev){showGlobalTip(ev,'<strong>'+rect.dataset.n+'</strong><br>Hosts: '+rect.dataset.h+' · Instancias: '+rect.dataset.i+'<br>VPR: '+rect.dataset.v+'<br><span style="font-size:0.68rem;color:var(--p);font-weight:700;margin-top:4px;display:block">Clic para ver hosts afectados</span>');});
      rect.addEventListener('mousemove',posGlobalTip);
      rect.addEventListener('mouseleave',hideGlobalTip);
      rect.addEventListener('click',function(){
         var item = rects[rect.dataset.idx].item;
         var vName = item.name;
         var hostsSet = new Set();
         filteredRaw.forEach(function(r){
            if(r.vulnName === vName) hostsSet.add(r.hostname);
         });
         var hostsArr = Array.from(hostsSet).sort();
         
         document.getElementById('modalHostname').textContent = vName;
         document.querySelector('#hostModal .modal-header .material-icons-round').textContent = 'bug_report';
         document.querySelector('#hostModal .modal-header .material-icons-round').style.color='var(--p)';
         
         var body = '<div style="margin-bottom:18px"><div class="modal-kpi"><div class="modal-kpi-item"><div class="mkv">'+hostsArr.length+'</div><div class="mkl">Hosts Afectados</div></div><div class="modal-kpi-item"><div class="mkv">'+item.inst+'</div><div class="mkl">Instancias</div></div><div class="modal-kpi-item"><div class="mkv"><span class="bd '+(item.vpr!=='N/A'?'bwa':'bof')+'">'+item.vpr+'</span></div><div class="mkl">Nivel VPR</div></div></div></div>';
         body += '<div style="margin-bottom:18px"><h3 style="font-family:var(--fd);font-size:.85rem;font-weight:500;margin-bottom:10px;display:flex;align-items:center;gap:6px;color:var(--p)"><span class="material-icons-round" style="font-size:16px">dns</span> Hosts afectados</h3><ul class="modal-vuln-list">';
         hostsArr.forEach(function(h){
           body += '<li style="cursor:pointer;transition:background .15s" onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'" onclick="openHostModal(\''+h+'\')"><span class="material-icons-round" style="color:var(--p)">dns</span><span style="flex:1;font-weight:500;margin-left:4px">'+h+'</span><span class="material-icons-round" style="font-size:14px;color:var(--t2);opacity:.5">open_in_new</span></li>';
         });
         body += '</ul></div>';
         
         document.getElementById('modalBody').innerHTML = body;
         document.getElementById('hostModal').classList.add('open');
         hideGlobalTip();
      });
    });
  }
  window._drawTreemap=drawTreemap; // F2-PERF: initial draw deferred to rT(false)


  // 5. BUBBLE — viewBox 440x360, ml=54
  function drawBubble(filteredRaw){
    var el=document.getElementById('bubbleArea');if(!el)return;
    var vcB={};filteredRaw.forEach(function(r){if(!r.vulnName)return;if(!vcB[r.vulnName])vcB[r.vulnName]={hosts:new Set(),count:0,ents:new Set(),vpr:r.nivelVPR};vcB[r.vulnName].hosts.add(r.hostname);vcB[r.vulnName].count++;vcB[r.vulnName].ents.add(r.entorno);});
    var items=Object.entries(vcB).sort(function(a,b){return b[1].hosts.size-a[1].hosts.size;}).slice(0,25).map(function(e){return{name:e[0],hosts:e[1].hosts.size,inst:e[1].count,ents:e[1].ents.size,vpr:e[1].vpr||'N/A'};});
    if(!items.length){el.innerHTML='<p style="color:var(--t2)">Sin datos</p>';return;}
    var W=440,H=360,ml=54,mr=40,mt=30,mb=42; // Aumentado mr para evitar corte eje X
    var cw=W-ml-mr,ch=H-mt-mb;
    var mxH=Math.max.apply(null,items.map(function(i){return i.hosts;}))||1;
    var mxI=Math.max.apply(null,items.map(function(i){return i.inst;}))||1;
    var mxE=Math.max.apply(null,items.map(function(i){return i.ents;}))||1;
    var s='';
    s+='<svg class="bub-svg" viewBox="0 0 '+W+' '+H+'">';
    for(var i=0;i<=4;i++){var y=mt+ch-ch*(i/4);s+='<line x1="'+ml+'" y1="'+y+'" x2="'+(ml+cw)+'" y2="'+y+'" stroke="var(--olv)" stroke-width="1"/>';s+='<text x="'+(ml-6)+'" y="'+y+'" text-anchor="end" dominant-baseline="middle" fill="var(--t2)" font-size="9" font-family="var(--fd)">'+Math.round(mxI/4*i)+'</text>';}
    for(var i=0;i<=4;i++){var x=ml+cw*(i/4);s+='<text x="'+x+'" y="'+(mt+ch+14)+'" text-anchor="middle" fill="var(--t2)" font-size="9" font-family="var(--fd)">'+Math.round(mxH/4*i)+'</text>';}
    s+='<text x="'+(ml+cw/2)+'" y="'+(H-6)+'" text-anchor="middle" fill="var(--t2)" font-size="10" font-weight="500" font-family="var(--fd)">Hosts afectados</text>';
    s+='<text x="14" y="'+(mt+ch/2)+'" text-anchor="middle" fill="var(--t2)" font-size="10" font-weight="500" font-family="var(--fd)" transform="rotate(-90 14 '+(mt+ch/2)+')">Instancias</text>';
    var sortedItems = items.slice().sort(function(a,b){return a.ents-b.ents;});
    sortedItems.forEach(function(it, i){
      var x=ml+cw*(it.hosts/mxH);var y=mt+ch-ch*(it.inst/mxI);
      var r=Math.max(5,Math.min(it.ents/mxE*18+4,22));
      var col=it.hosts>mxH*0.5?'#D14600':it.hosts>mxH*0.25?'#FFAE41':'#4995FF';
      s+='<circle class="bub-circle" data-idx="'+i+'" cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="'+r.toFixed(1)+'" fill="'+col+'" opacity=".6" stroke="'+col+'" stroke-width="1" stroke-opacity=".3" data-n="'+it.name.replace(/"/g,'&quot;')+'" data-h="'+it.hosts+'" data-i="'+it.inst+'" data-e="'+it.ents+'" data-v="'+it.vpr+'"/>';
    });
    s+='</svg>';
    s+='<div style="text-align:center;font-size:.68rem;color:var(--t2);margin-top:4px">Tamaño = nº entornos afectados</div>';
    el.innerHTML=s;
    el.querySelectorAll('.bub-circle').forEach(function(c){
      c.addEventListener('mouseenter',function(ev){showGlobalTip(ev,'<strong>'+c.dataset.n+'</strong><br>Hosts: '+c.dataset.h+' · Instancias: '+c.dataset.i+'<br>Entornos: '+c.dataset.e+' · VPR: '+c.dataset.v+'<br><span style="font-size:0.68rem;color:var(--p);font-weight:700;margin-top:4px;display:block">Clic para ver hosts afectados</span>');});
      c.addEventListener('mousemove',posGlobalTip);
      c.addEventListener('mouseleave',hideGlobalTip);
      c.addEventListener('click',function(){
         var item = sortedItems[c.dataset.idx];
         var vName = item.name;
         var hostsSet = new Set();
         filteredRaw.forEach(function(r){
            if(r.vulnName === vName) hostsSet.add(r.hostname);
         });
         var hostsArr = Array.from(hostsSet).sort();
         
         document.getElementById('modalHostname').textContent = vName;
         document.querySelector('#hostModal .modal-header .material-icons-round').textContent = 'bug_report';
         document.querySelector('#hostModal .modal-header .material-icons-round').style.color='var(--p)';
         
         var body = '<div style="margin-bottom:18px"><div class="modal-kpi"><div class="modal-kpi-item"><div class="mkv">'+hostsArr.length+'</div><div class="mkl">Hosts Afectados</div></div><div class="modal-kpi-item"><div class="mkv">'+item.inst+'</div><div class="mkl">Instancias</div></div><div class="modal-kpi-item"><div class="mkv">'+item.ents+'</div><div class="mkl">Entornos</div></div><div class="modal-kpi-item"><div class="mkv"><span class="bd '+(item.vpr!=='N/A'?'bwa':'bof')+'">'+item.vpr+'</span></div><div class="mkl">Nivel VPR</div></div></div></div>';
         body += '<div style="margin-bottom:18px"><h3 style="font-family:var(--fd);font-size:.85rem;font-weight:500;margin-bottom:10px;display:flex;align-items:center;gap:6px;color:var(--p)"><span class="material-icons-round" style="font-size:16px">dns</span> Hosts afectados</h3><ul class="modal-vuln-list">';
         hostsArr.forEach(function(h){
           body += '<li style="cursor:pointer;transition:background .15s" onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'" onclick="openHostModal(\''+h+'\')"><span class="material-icons-round" style="color:var(--p)">dns</span><span style="flex:1;font-weight:500;margin-left:4px">'+h+'</span><span class="material-icons-round" style="font-size:14px;color:var(--t2);opacity:.5">open_in_new</span></li>';
         });
         body += '</ul></div>';
         
         document.getElementById('modalBody').innerHTML = body;
         document.getElementById('hostModal').classList.add('open');
         hideGlobalTip();
      });
    });
  }
  // F2-PERF: drawBubble(raw) removed — deferred to rT(false)

  // ENV SUMMARY — Qualys Business Entity style
  (function(){var ec=['var(--p)','#D14600','#1a7a32','#FFAE41','#004AAC','#FFC982'];var h='';
    var activeEnts=ents.filter(function(e){return e[1]>0;});
    var maxEnvVulns = activeEnts.length>0 ? Math.max.apply(null, activeEnts.map(function(e){ return raw.filter(function(x){return x.entorno===e[0];}).length; })) : 1;
    activeEnts.forEach(function(e,i){var env=e[0],cnt=e[1];
      var eH=hosts.filter(function(x){return x.entorno===env;});
      var eV=raw.filter(function(x){return x.entorno===env;});
      var eHab=eH.filter(function(x){return x.estadoAD==='HABILITADO';}).length;
      var eCrit=eH.filter(function(x){return x.estadoAD==='HABILITADO'&&x.diasQualys>15&&x.diasLogon>15;}).length;
      var aQ=eH.length?Math.round(eH.reduce(function(s,x){return s+x.diasQualys;},0)/eH.length):0;
      var vph=eH.length?(eV.length/eH.length).toFixed(1):0;
      var eKEV=window._kevSet?eV.filter(function(r){return r.isKEV}).length:0;

      var rScore = 0;
      if(eH.length > 0){
        // "Rating 9.0 a 10.0" → critical (avoid matching "8.9" which also has a 9)
        var critVulns = eV.filter(function(r){return r.nivelVPR&&r.nivelVPR.indexOf('9.0')>=0;}).length;
        var wSev = critVulns/Math.max(eV.length,1)*25;          // % critical severity (25pts)
        var wCrit = eCrit/Math.max(eH.length,1)*20;             // % hosts critical state (20pts)
        var wQ = Math.min(aQ/60,1)*15;                          // avg days, 60d=max (15pts)
        var wKEV = Math.min(eKEV/10,1)*20;                      // KEV count, 10+=max (20pts)
        var wDensity = Math.min(parseFloat(vph)/15,1)*10;       // vulns/host, 15+=max (10pts)
        var wGhost = (1 - eHab/Math.max(cnt,1))*10;             // % disabled=ghost risk (10pts)
        rScore = Math.min(Math.round(wSev+wCrit+wQ+wKEV+wDensity+wGhost), 100);
      }
      var rColor = rScore>=70?'var(--err)':rScore>=40?'var(--warn)':'var(--ok)';
      var vulnPct = Math.round(eV.length/maxEnvVulns*100);
      var accentColor = ec[i%ec.length];

      // Mini gauge SVG
      var gSize=56, gR=(gSize/2)-3, gC=Math.PI*gR, gPct=Math.min(rScore/100,1);
      var miniGauge='<svg width="'+gSize+'" height="'+(gSize/2+6)+'" viewBox="0 0 '+gSize+' '+(gSize/2+6)+'">'
        +'<path d="M3,'+(gSize/2+3)+' A'+gR+','+gR+' 0 0,1 '+(gSize-3)+','+(gSize/2+3)+'" fill="none" stroke="var(--s2)" stroke-width="5" stroke-linecap="round"/>'
        +'<path d="M3,'+(gSize/2+3)+' A'+gR+','+gR+' 0 0,1 '+(gSize-3)+','+(gSize/2+3)+'" fill="none" stroke="'+rColor+'" stroke-width="5" stroke-linecap="round" stroke-dasharray="'+gC+'" stroke-dashoffset="'+(gC*(1-gPct))+'" style="transition:stroke-dashoffset .8s"/>'
        +'<text x="'+(gSize/2)+'" y="'+(gSize/2-1)+'" text-anchor="middle" font-family="var(--fd)" font-size="14" font-weight="700" fill="var(--t)">'+rScore+'</text>'
        +'</svg>';

      h+='<div class="env-card" style="border-top:4px solid '+accentColor+';padding:0;overflow:hidden">';
      // Header row: icon + name + gauge
      h+='<div style="display:flex;align-items:center;gap:10px;padding:14px 16px 0">'
        +'<div style="flex:1;min-width:0"><h4 style="margin-bottom:0">'+getEnvIcon(env)+' <span style="margin-left:4px">'+env+'</span></h4>'
        +'<div style="font-size:.62rem;color:var(--t2);margin-top:2px">'+cnt+' equipos · '+eV.length+' vulnerabilidades</div></div>'
        +'<div style="text-align:center;flex-shrink:0">'+miniGauge+'<div style="font-size:.5rem;color:var(--t2);text-transform:uppercase;letter-spacing:.3px;margin-top:1px">Riesgo</div></div>'
        +'</div>';

      // Exposure bar
      h+='<div style="padding:10px 16px 0"><div style="height:6px;background:var(--s2);border-radius:3px;overflow:hidden;position:relative">'
        +'<div style="height:100%;width:'+vulnPct+'%;background:linear-gradient(90deg,'+accentColor+','+accentColor+'88);border-radius:3px;transition:width .6s"></div>'
        +'</div></div>';

      // Key metrics — 2x2 grid focused on what matters
      h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:1px;margin:10px 16px 0;background:var(--olv);border-radius:8px;overflow:hidden">';
      // Habilitados vs Total
      h+='<div style="background:var(--s1);padding:8px 10px;text-align:center"><div style="font-family:var(--fd);font-size:1rem;font-weight:700;color:var(--ok)">'+eHab+'<span style="font-size:.7rem;font-weight:400;color:var(--t2)">/'+cnt+'</span></div><div style="font-size:.52rem;color:var(--t2);text-transform:uppercase;letter-spacing:.3px">Habilitados</div></div>';
      // Críticos
      h+='<div style="background:var(--s1);padding:8px 10px;text-align:center"><div style="font-family:var(--fd);font-size:1rem;font-weight:700;color:'+(eCrit>0?'var(--err)':'var(--ok)')+'">'+eCrit+'</div><div style="font-size:.52rem;color:var(--t2);text-transform:uppercase;letter-spacing:.3px">Críticos</div></div>';
      // Avg Días Q
      h+='<div style="background:var(--s1);padding:8px 10px;text-align:center"><div style="font-family:var(--fd);font-size:1rem;font-weight:700;color:'+(aQ>30?'var(--err)':aQ>15?'var(--warn)':'var(--ok)')+'">'+aQ+'<span style="font-size:.65rem;font-weight:400">d</span></div><div style="font-size:.52rem;color:var(--t2);text-transform:uppercase;letter-spacing:.3px">Avg Días Q</div></div>';
      // KEV or Vulns/Host
      if(eKEV > 0){
        h+='<div style="background:var(--s1);padding:8px 10px;text-align:center"><div style="font-family:var(--fd);font-size:1rem;font-weight:700;color:var(--err)">'+eKEV+'</div><div style="font-size:.52rem;color:var(--t2);text-transform:uppercase;letter-spacing:.3px">KEV Activos</div></div>';
      } else {
        h+='<div style="background:var(--s1);padding:8px 10px;text-align:center"><div style="font-family:var(--fd);font-size:1rem;font-weight:700">'+vph+'</div><div style="font-size:.52rem;color:var(--t2);text-transform:uppercase;letter-spacing:.3px">Vulns/Host</div></div>';
      }
      h+='</div>';

      // Bottom insight
      var insight = eCrit > 0 ? '<span style="color:var(--err)"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">warning</span> '+eCrit+' host'+(eCrit>1?'s':'')+' en estado crítico</span>'
        : eKEV > 0 ? '<span style="color:var(--err)"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">shield</span> '+eKEV+' instancias KEV</span>'
        : aQ > 30 ? '<span style="color:var(--warn)"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">schedule</span> Antigüedad alta: '+aQ+'d</span>'
        : '<span style="color:var(--ok)"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">check_circle</span> Estado aceptable</span>';
      h+='<div style="padding:8px 16px 12px;font-size:.65rem;font-weight:500">'+insight+'</div>';

      h+='</div>';
    });
    document.getElementById('envGrid').innerHTML=h;})();


  // GHOSTS
  (function(){var gh=hosts.filter(function(h){return h.estadoAD==='DESHABILITADO'||h.diasQualys>90;});var gD=gh.filter(function(h){return h.estadoAD==='DESHABILITADO';});var gN=gh.filter(function(h){return h.diasQualys>90&&h.estadoAD!=='DESHABILITADO';});
    var h='<p style="margin-top:4px">Deshabilitados en AD o sin escaneo >90d.</p><div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0"><div class="ghost-stat"><span class="material-icons-round" style="font-size:13px">cancel</span> '+gD.length+' deshab.</div><div class="ghost-stat" style="background:var(--warnc);color:var(--warn)"><span class="material-icons-round" style="font-size:13px">schedule</span> '+gN.length+' sin escaneo >90d</div></div>';
    if(gh.length){h+='<div class="ghost-list">';gh.slice(0,40).forEach(function(x){h+='<div class="ghost-chip" onclick="openHostModal(\''+x.hostname+'\')"><span class="material-icons-round">'+(x.estadoAD==='DESHABILITADO'?'cancel':'schedule')+'</span>'+x.hostname+' <span style="opacity:.6;font-size:.62rem">'+x.diasQualys+'d</span></div>';});if(gh.length>40)h+='<div class="ghost-chip">+'+(gh.length-40)+' más</div>';h+='</div>';}
    document.getElementById('ghostArea').innerHTML=h;})();

  // PATCH DAYS
  (function(){var bk=[{l:'0-3d',a:0,b:3,c:'var(--ok)'},{l:'4-7d',a:4,b:7,c:'#2a9d48'},{l:'8-15d',a:8,b:15,c:'#66bb6a'},{l:'16-30d',a:16,b:30,c:'var(--warn)'},{l:'31-60d',a:31,b:60,c:'#FF7E51'},{l:'61-90d',a:61,b:90,c:'var(--err)'},{l:'>90d',a:91,b:9999,c:'#8f2e00'}];
    var cs=bk.map(function(b){return{l:b.l,a:b.a,b:b.b,c:b.c,hosts:hosts.filter(function(h){return h.diasQualys>=b.a&&h.diasQualys<=b.b;})};});var mx=Math.max.apply(null,cs.map(function(c){return c.hosts.length;}).concat([1]));
    var h='<div style="display:flex;gap:8px;align-items:flex-end;height:160px;padding:15px 0 10px;justify-content:center">';
    cs.forEach(function(b,idx){var ht=Math.max(b.hosts.length/mx*110,4);h+='<div class="pd-bar" data-idx="'+idx+'" style="display:flex;flex-direction:column;align-items:center;gap:4px;flex:1;max-width:100px;cursor:pointer;transition:opacity .15s" onmouseover="this.style.opacity=\'.7\'" onmouseout="this.style.opacity=\'1\'"><span style="font-family:var(--fd);font-weight:700;font-size:.78rem">'+b.hosts.length+'</span><div style="width:100%;height:'+ht+'px;background:'+b.c+';border-radius:6px 6px 0 0"></div><span style="font-size:.65rem;color:var(--t2);font-weight:500">'+b.l+'</span></div>';});
    h+='</div>';document.getElementById('patchDays').innerHTML=h;
    
    document.querySelectorAll('.pd-bar').forEach(function(bar){
      bar.addEventListener('click',function(){
        var item=cs[bar.dataset.idx];
        var hList=item.hosts.sort(function(a,b){return b.diasQualys-a.diasQualys;});
        document.getElementById('modalHostname').textContent='Antigüedad: '+item.l;
        document.querySelector('#hostModal .modal-header .material-icons-round').textContent='event_busy';
        document.querySelector('#hostModal .modal-header .material-icons-round').style.color='var(--p)';
        var body='<div style="margin-bottom:18px"><div class="modal-kpi"><div class="modal-kpi-item"><div class="mkv">'+hList.length+'</div><div class="mkl">Equipos</div></div><div class="modal-kpi-item"><div class="mkv">'+item.a+(item.b<9999?' a '+item.b:'+')+'</div><div class="mkl">Días Qualys</div></div></div></div>';
        if(hList.length>0){
          body+='<div style="margin-bottom:18px"><h3 style="font-family:var(--fd);font-size:.85rem;font-weight:500;margin-bottom:10px;display:flex;align-items:center;gap:6px;color:var(--p)"><span class="material-icons-round" style="font-size:16px">dns</span> Equipos en este rango</h3><ul class="modal-vuln-list">';
          hList.forEach(function(h){
            body+='<li style="cursor:pointer;transition:background .15s" onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'" onclick="openHostModal(\''+h.hostname+'\')"><span class="material-icons-round" style="color:'+item.c+'">dns</span><span style="flex:1;font-weight:500;margin-left:4px">'+h.hostname+'</span><span class="bd bof" style="margin-right:8px">'+h.diasQualys+'d</span><span class="material-icons-round" style="font-size:14px;color:var(--t2);opacity:.5">open_in_new</span></li>';
          });
          body+='</ul></div>';
        }else{
          body+='<p style="color:var(--t2);font-size:.8rem;text-align:center;padding:20px 0">No hay equipos en este rango.</p>';
        }
        document.getElementById('modalBody').innerHTML=body;
        document.getElementById('hostModal').classList.add('open');
        hideGlobalTip();
      });
      bar.addEventListener('mouseenter',function(ev){showGlobalTip(ev,'<strong>Rango '+cs[bar.dataset.idx].l+'</strong><br>Equipos: '+cs[bar.dataset.idx].hosts.length+'<br><span style="font-size:0.68rem;color:var(--p);font-weight:700;margin-top:4px;display:block">Clic para ver equipos</span>');});
      bar.addEventListener('mousemove',posGlobalTip);
      bar.addEventListener('mouseleave',hideGlobalTip);
    });
  })();

  // SVG DONUT
  function svgDonut(containerId,segs,total,centerLabel){
    var el=document.getElementById(containerId);if(!el)return;
    var R=60,r=42,cx=75,cy=75,S=160;
    var svg='<svg class="donut-svg" viewBox="0 0 '+S+' '+S+'" style="width:150px;height:150px">';
    var a=-Math.PI/2;
    segs.forEach(function(s,i){
      if(s.value<=0)return;
      var sw=total>0?(s.value/total)*Math.PI*2:0;
      var la=sw>Math.PI?1:0;
      var x1=cx+R*Math.cos(a),y1=cy+R*Math.sin(a);
      var x2=cx+R*Math.cos(a+sw),y2=cy+R*Math.sin(a+sw);
      var ix1=cx+r*Math.cos(a+sw),iy1=cy+r*Math.sin(a+sw);
      var ix2=cx+r*Math.cos(a),iy2=cy+r*Math.sin(a);
      var pct=total>0?(s.value/total*100).toFixed(1):'0';
      svg+='<path class="seg" data-i="'+i+'" d="M'+x1+' '+y1+' A'+R+' '+R+' 0 '+la+' 1 '+x2+' '+y2+' L'+ix1+' '+iy1+' A'+r+' '+r+' 0 '+la+' 0 '+ix2+' '+iy2+' Z" fill="'+s.color+'"/>';
      a+=sw;
    });
    svg+='<text x="'+cx+'" y="'+(cy-4)+'" text-anchor="middle" dominant-baseline="middle" fill="var(--t)" font-family="var(--fd)" font-weight="700" font-size="18">'+total+'</text>';
    svg+='<text x="'+cx+'" y="'+(cy+12)+'" text-anchor="middle" fill="var(--t2)" font-family="var(--fd)" font-size="9">'+(centerLabel||'Total')+'</text>';
    svg+='</svg>';
    var legend='<div class="donut-legend">';
    segs.forEach(function(s){
      var pct=total>0?(s.value/total*100).toFixed(1):'0';
      legend+='<div class="li" title="'+s.label+'"><span class="ld" style="background:'+s.color+'"></span><span>'+s.label+'</span><span class="lv">'+s.value+' <span style="opacity:.6;font-size:.6rem">('+pct+'%)</span></span></div>';
    });
    legend+='</div>';
    el.innerHTML=svg+legend;
    el.querySelectorAll('.seg').forEach(function(seg){
      seg.addEventListener('mouseenter',function(ev){
        var idx=+seg.dataset.i;var s=segs[idx];var pct=total>0?(s.value/total*100).toFixed(1):'0';
        showGlobalTip(ev,'<strong>'+s.label+'</strong> '+s.value+' ('+pct+'%)');
      });
      seg.addEventListener('mousemove',posGlobalTip);
      seg.addEventListener('mouseleave',hideGlobalTip);
    });
  }
  svgDonut('dEst',[{label:'Habilitados',value:hab.length,color:'#1a7a32'},{label:'Deshabilitados',value:des.length,color:'#D14600'},{label:'Sin Estado',value:sin.length,color:'#FFAE41'}],tH,'Con Vulns');

  // F7-PERF: use global normEnv instead of local normEnvKey
  function normEnvKey(e){return normEnv(e);}

  // Evolution chart — línea TOTAL + desglose por entorno
  function renderEvoLines(metric,label){
    var area=document.getElementById('evoChartArea');
    var snaps=window._snapshots;
    if(!area||!snaps||snaps.length<2)return;

    // Construir mapa normalizado de entornos: normKey → displayName
    var envMap={};  // normKey → displayName
    ['Portatil','Cajero','Fijo','Virtual','Actualizador','Apple'].forEach(function(e){envMap[e]=e;});
    snaps.forEach(function(s){
      if(s.byEnv) Object.keys(s.byEnv).forEach(function(rawKey){
        var nk=normEnvKey(rawKey);
        if(!envMap[nk]) envMap[nk]=rawKey; // guarda el display original
      });
    });
    var normKeys=Object.keys(envMap);
    var palette=['#4995FF','#D14600','#1a7a32','#FFAE41','#004AAC','#FF7E51','#A1E6FF','#FFC982'];
    var envColors={};
    normKeys.forEach(function(nk,i){envColors[nk]=palette[i%palette.length];});

    // Función para obtener valor por entorno, buscando por clave normalizada
    function getEnvVal(snap, normKey, met){
      if(!snap.byEnv) return 0;
      // Buscar clave exacta primero
      if(snap.byEnv[normKey]) return snap.byEnv[normKey][met]||0;
      // Buscar por normalización
      var found=0;
      Object.keys(snap.byEnv).forEach(function(k){
        if(normEnvKey(k)===normKey) found=(snap.byEnv[k][met]||0);
      });
      return found;
    }

    // gMax = max entre el total del snapshot y los valores por entorno
    var gMax=0;
    snaps.forEach(function(s){
      var tv=s[metric]||0; if(tv>gMax)gMax=tv;
      normKeys.forEach(function(nk){var v=getEnvVal(s,nk,metric);if(v>gMax)gMax=v;});
    });
    gMax=gMax||1;

    var W=900,H=300,ml=60,mr=20,mt=20,mb=52;
    var cw=W-ml-mr,ch=H-mt-mb;
    var n=snaps.length;
    var s='<div class="evo-line-wrap"><svg viewBox="0 0 '+W+' '+H+'" style="overflow:visible">';

    // Grid + Y labels
    for(var gi=0;gi<=4;gi++){
      var gy=mt+ch-ch*(gi/4);
      s+='<line x1="'+ml+'" y1="'+gy+'" x2="'+(ml+cw)+'" y2="'+gy+'" stroke="var(--olv)" stroke-width="1"/>';
      s+='<text x="'+(ml-6)+'" y="'+gy+'" text-anchor="end" dominant-baseline="middle" fill="var(--t2)" font-size="10" font-family="var(--fd)">'+Math.round(gMax/4*gi)+'</text>';
    }
    // Y axis label
    s+='<text x="14" y="'+(mt+ch/2)+'" text-anchor="middle" fill="var(--t2)" font-size="10" font-weight="500" font-family="var(--fd)" transform="rotate(-90 14 '+(mt+ch/2)+')">'+label+'</text>';
    // X labels
    for(var xi=0;xi<n;xi++){
      var xx=ml+cw*(xi/(n>1?n-1:1));
      var lbl=snaps[xi].name.replace(/\.[^.]+$/,'').replace(/^scan_/,'');
      if(lbl.length>14) lbl=lbl.substring(0,13)+'…';
      var tw=(xi===fIndex)?'700':'500';
      var tc=(xi===fIndex)?'var(--p)':'var(--t2)';
      s+='<text x="'+xx.toFixed(1)+'" y="'+(mt+ch+16)+'" text-anchor="middle" fill="'+tc+'" font-weight="'+tw+'" font-size="9" font-family="var(--fd)">'+lbl+'</text>';
      // Vertical marker for selected snapshot
      if(xi===fIndex) s+='<line x1="'+xx.toFixed(1)+'" y1="'+mt+'" x2="'+xx.toFixed(1)+'" y2="'+(mt+ch)+'" stroke="var(--p)" stroke-width="1" stroke-dasharray="4 3" opacity=".5"/>';
    }
    // Axes
    s+='<line x1="'+ml+'" y1="'+mt+'" x2="'+ml+'" y2="'+(mt+ch)+'" stroke="var(--ol)" stroke-width="1"/>';
    s+='<line x1="'+ml+'" y1="'+(mt+ch)+'" x2="'+(ml+cw)+'" y2="'+(mt+ch)+'" stroke="var(--ol)" stroke-width="1"/>';

    // --- LÍNEA TOTAL (negrita, azul) ---
    var totalPts=[];
    snaps.forEach(function(snap,i){
      var v=snap[metric]||0;
      var x=ml+cw*(i/(n>1?n-1:1));
      var y=mt+ch-ch*(v/gMax);
      totalPts.push(x.toFixed(1)+','+y.toFixed(1));
    });
    s+='<polyline points="'+totalPts.join(' ')+'" fill="none" stroke="var(--p)" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" opacity=".9"/>';
    snaps.forEach(function(snap,i){
      var v=snap[metric]||0;
      var x=ml+cw*(i/(n>1?n-1:1));
      var y=mt+ch-ch*(v/gMax);
      var isSelected=(i===fIndex);
      var r=isSelected?7:4;
      var fw=isSelected?'3':'2';
      s+='<circle class="evo-line-dot" cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="'+r+'" fill="'+(isSelected?'#fff':'var(--p)')+'" stroke="var(--p)" stroke-width="'+fw+'" data-n="'+snap.name+'" data-v="'+v+'" data-l="Total · '+label+'" data-ex="'+(isSelected?'<br><span style=color:var(--p);font-weight:700>Fecha Seleccionada</span>':'')+'"/>';
      // Value label above dot
      s+='<text x="'+x.toFixed(1)+'" y="'+(y-10).toFixed(1)+'" text-anchor="middle" fill="var(--p)" font-size="10" font-weight="700" font-family="var(--fd)">'+v+'</text>';
    });

    // --- LÍNEAS POR ENTORNO (finas) ---
    normKeys.forEach(function(nk){
      var col=envColors[nk];
      var pts=[];
      snaps.forEach(function(snap,i){
        var v=getEnvVal(snap,nk,metric);
        var x=ml+cw*(i/(n>1?n-1:1));
        var y=mt+ch-ch*(v/gMax);
        pts.push(x.toFixed(1)+','+y.toFixed(1));
      });
      s+='<polyline points="'+pts.join(' ')+'" fill="none" stroke="'+col+'" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" opacity=".7" stroke-dasharray="5 3"/>';
      snaps.forEach(function(snap,i){
        var v=getEnvVal(snap,nk,metric);
        if(v===0) return; // No dibujar puntos vacíos
        var x=ml+cw*(i/(n>1?n-1:1));
        var y=mt+ch-ch*(v/gMax);
        s+='<circle class="evo-line-dot" cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="3" fill="'+col+'" stroke="'+col+'" stroke-width="1" data-n="'+snap.name+'" data-v="'+v+'" data-l="'+(envMap[nk]||nk)+' · '+label+'" data-ex=""/>';
      });
    });

    s+='</svg></div>';
    // Legend
    s+='<div class="evo-legend">';
    s+='<span style="display:inline-flex;align-items:center;gap:4px"><span class="edot" style="background:var(--p);width:12px;height:4px;border-radius:2px"></span><strong>Total</strong></span>';
    normKeys.forEach(function(nk){
      var dispName=envMap[nk]||nk;
      s+='<span style="display:inline-flex;align-items:center;gap:4px"><span class="edot" style="background:'+envColors[nk]+'"></span>'+getEnvIcon(dispName)+' '+dispName+'</span>';
    });
    s+='</div>';
    area.innerHTML=s;
    // Usar zonas de captura más grandes para evitar flicker en SVG circles pequeños
    area.querySelectorAll('.evo-line-dot').forEach(function(dot){
      dot.addEventListener('mouseenter',function(){
        cancelHideGlobalTip();
        globalTip.innerHTML='<strong>'+dot.dataset.l+'</strong>: '+dot.dataset.v+'<br><span style="color:var(--t2);font-size:.65rem">'+dot.dataset.n+'</span>'+dot.dataset.ex;
        globalTip.classList.add('show');
        posGlobalTipAtEl(dot);
      });
      dot.addEventListener('mouseleave',hideGlobalTip);
    });
    // Hit areas: círculos invisibles más grandes sobre cada dot para captura más robusta
    area.querySelectorAll('.evo-line-dot').forEach(function(dot){
      var cx=dot.getAttribute('cx'), cy=dot.getAttribute('cy');
      var hit=document.createElementNS('http://www.w3.org/2000/svg','circle');
      hit.setAttribute('cx',cx); hit.setAttribute('cy',cy);
      hit.setAttribute('r','10'); hit.setAttribute('fill','transparent');
      hit.style.cursor='default';
      dot.parentNode.appendChild(hit);
      hit.addEventListener('mouseenter',function(){
        cancelHideGlobalTip();
        globalTip.innerHTML='<strong>'+dot.dataset.l+'</strong>: '+dot.dataset.v+'<br><span style="color:var(--t2);font-size:.65rem">'+dot.dataset.n+'</span>'+dot.dataset.ex;
        globalTip.classList.add('show');
        posGlobalTipAtEl(dot);
      });
      hit.addEventListener('mouseleave',hideGlobalTip);
    });
  }
  // Initial render and metric tab listeners
  if(window._snapshots&&window._snapshots.length>1){
    renderEvoLines('totalH','Equipos con Vulns');
    document.querySelectorAll('.evo-mbtn').forEach(function(btn){
      btn.addEventListener('click',function(){
        document.querySelectorAll('.evo-mbtn').forEach(function(b){b.classList.remove('active');});
        btn.classList.add('active');
        renderEvoLines(btn.dataset.metric,btn.dataset.label);
      });
    });
  }

  // RISK QUADRANT - Scatter Días Q vs Días AD
  function drawQuadrant(filtHosts){
    var el=document.getElementById('quadArea');if(!el)return;
    var W=620,H=380,ml=56,mr=40,mt=24,mb=44; // Aumentado mr para el valor extremo en X
    var cw=W-ml-mr,ch=H-mt-mb;
    var mxQ=Math.max.apply(null,filtHosts.map(function(h){return h.diasQualys;}).concat([30]));
    var mxA=Math.max.apply(null,filtHosts.map(function(h){return h.diasLogon;}).concat([30]));
    mxQ=Math.ceil(mxQ*1.1);mxA=Math.ceil(mxA*1.1);
    var s='';
    s+='<p class="quad-sub" style="margin-top:0">Cada punto = 1 host. Superior-derecho = crítico</p>';
    s+='<div class="quad-svg-wrap"><svg viewBox="0 0 '+W+' '+H+'" xmlns="http://www.w3.org/2000/svg">';
    // Quadrant backgrounds
    var x15=ml+cw*(15/mxQ),y15=mt+ch-ch*(15/mxA);
    s+='<rect x="'+ml+'" y="'+y15+'" width="'+(x15-ml)+'" height="'+(mt+ch-y15)+'" fill="var(--okc)" opacity=".3"/>';
    s+='<rect x="'+x15+'" y="'+y15+'" width="'+(ml+cw-x15)+'" height="'+(mt+ch-y15)+'" fill="var(--warnc)" opacity=".3"/>';
    s+='<rect x="'+ml+'" y="'+mt+'" width="'+(x15-ml)+'" height="'+(y15-mt)+'" fill="var(--warnc)" opacity=".3"/>';
    s+='<rect x="'+x15+'" y="'+mt+'" width="'+(ml+cw-x15)+'" height="'+(y15-mt)+'" fill="var(--errc)" opacity=".4"/>';
    // Zone labels
    s+='<text x="'+((ml+x15)/2)+'" y="'+(mt+ch-8)+'" text-anchor="middle" fill="var(--ok)" font-size="9" font-weight="700" opacity=".6">OK</text>';
    s+='<text x="'+((x15+ml+cw)/2)+'" y="'+(mt+ch-8)+'" text-anchor="middle" fill="var(--warn)" font-size="9" font-weight="700" opacity=".6">Solo +Q</text>';
    s+='<text x="'+((ml+x15)/2)+'" y="'+(mt+12)+'" text-anchor="middle" fill="var(--warn)" font-size="9" font-weight="700" opacity=".6">Solo +AD</text>';
    s+='<text x="'+((x15+ml+cw)/2)+'" y="'+(mt+12)+'" text-anchor="middle" fill="var(--err)" font-size="9" font-weight="700" opacity=".6">CRÍTICO</text>';
    // Threshold lines
    s+='<line x1="'+x15+'" y1="'+mt+'" x2="'+x15+'" y2="'+(mt+ch)+'" stroke="var(--err)" stroke-width="1" stroke-dasharray="4 3" opacity=".5"/>';
    s+='<line x1="'+ml+'" y1="'+y15+'" x2="'+(ml+cw)+'" y2="'+y15+'" stroke="var(--err)" stroke-width="1" stroke-dasharray="4 3" opacity=".5"/>';
    // Axes
    s+='<line x1="'+ml+'" y1="'+(mt+ch)+'" x2="'+(ml+cw)+'" y2="'+(mt+ch)+'" stroke="var(--ol)" stroke-width="1"/>';
    s+='<line x1="'+ml+'" y1="'+mt+'" x2="'+ml+'" y2="'+(mt+ch)+'" stroke="var(--ol)" stroke-width="1"/>';
    // X ticks
    for(var i=0;i<=4;i++){var v=Math.round(mxQ/4*i);var x=ml+cw*(v/mxQ);s+='<text x="'+x+'" y="'+(mt+ch+14)+'" text-anchor="middle" fill="var(--t2)" font-size="9">'+v+'d</text>';}
    // Y ticks
    for(var i=0;i<=4;i++){var v=Math.round(mxA/4*i);var y=mt+ch-ch*(v/mxA);s+='<text x="'+(ml-6)+'" y="'+y+'" text-anchor="end" dominant-baseline="middle" fill="var(--t2)" font-size="9">'+v+'d</text>';}
    // Axis labels
    s+='<text x="'+(ml+cw/2)+'" y="'+(H-4)+'" text-anchor="middle" fill="var(--t2)" font-size="10" font-weight="500">Días Qualys</text>';
    s+='<text x="10" y="'+(mt+ch/2)+'" text-anchor="middle" fill="var(--t2)" font-size="10" font-weight="500" transform="rotate(-90 10 '+(mt+ch/2)+')">Días Logon AD</text>';
    // Dots
    filtHosts.forEach(function(h){
      var x=ml+cw*(Math.min(h.diasQualys,mxQ)/mxQ);
      var y=mt+ch-ch*(Math.min(h.diasLogon,mxA)/mxA);
      var col=h.estadoAD==='HABILITADO'&&h.diasQualys>15&&h.diasLogon>15?'#D14600':h.diasQualys>15||h.diasLogon>15?'#FFAE41':'#1a7a32';
      s+='<circle class="quad-dot" cx="'+x+'" cy="'+y+'" r="4" fill="'+col+'" opacity=".7" data-h="'+h.hostname.replace(/"/g,'&quot;')+'" data-q="'+h.diasQualys+'" data-a="'+h.diasLogon+'" data-v="'+h.vc+'"/>';
    });
    s+='</svg></div>';
    // Counts per zone
    var zOK=filtHosts.filter(function(h){return h.diasQualys<=15&&h.diasLogon<=15;}).length;
    var zQ=filtHosts.filter(function(h){return h.diasQualys>15&&h.diasLogon<=15;}).length;
    var zA=filtHosts.filter(function(h){return h.diasQualys<=15&&h.diasLogon>15;}).length;
    var zC=filtHosts.filter(function(h){return h.diasQualys>15&&h.diasLogon>15;}).length;
    s+='<div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:10px;font-size:.72rem">';
    s+='<span style="color:var(--ok)"><strong>'+zOK+'</strong> OK</span>';
    s+='<span style="color:var(--warn)"><strong>'+zQ+'</strong> Solo +Q</span>';
    s+='<span style="color:var(--warn)"><strong>'+zA+'</strong> Solo +AD</span>';
    s+='<span style="color:var(--err)"><strong>'+zC+'</strong> Crítico</span></div>';
    el.innerHTML=s;
    el.querySelectorAll('.quad-dot').forEach(function(dot){
      dot.addEventListener('mouseenter',function(ev){
        showGlobalTip(ev,'<strong>'+dot.dataset.h+'</strong><br>Q: '+dot.dataset.q+'d · AD: '+dot.dataset.a+'d · Vulns: '+dot.dataset.v);
      });
      dot.addEventListener('mousemove',posGlobalTip);
      dot.addEventListener('mouseleave',hideGlobalTip);
      dot.addEventListener('click',function(){openHostModal(dot.dataset.h);});
    });
  }
  // F2-PERF: drawQuadrant(hosts) removed — deferred to rT(false)

  // TOP 10 HOSTS
  function drawTopHosts(filtHosts){
    var el=document.getElementById('tophArea');if(!el)return;
    var sorted=filtHosts.slice().sort(function(a,b){return b.vc-a.vc;}).slice(0,10);
    var mx=sorted[0]?sorted[0].vc:1;
    var h='';
    sorted.forEach(function(d,i){
      var w=d.vc/mx*100;
      var col=d.estadoAD==='HABILITADO'&&d.diasQualys>15&&d.diasLogon>15?'#D14600':d.diasQualys>15||d.diasLogon>15?'#FFAE41':'#4995FF';
      h+='<div class="toph-row" onclick="openHostModal(\''+d.hostname+'\')">';
      h+='<div class="toph-rank">'+(i+1)+'</div>';
      h+='<div class="toph-name" title="'+d.hostname+'">'+d.hostname+'</div>';
      h+='<div class="toph-bar-bg"><div class="toph-bar-fill" style="width:'+w+'%;background:'+col+'"></div></div>';
      h+='<div class="toph-val">'+d.vc+'</div></div>';
    });
    el.innerHTML=h;
  }
  // F2-PERF: drawTopHosts(hosts) removed — deferred to rT(false)

  // STATE
  var tQMin=0,tQMax=maxQ,tAMin=0,tAMax=maxAD,fLg='AND',curTab='eq',sEq={key:'diasQualys',dir:'desc'},sVu={key:'diasQualys',dir:'desc'},pgEq=1,pgVu=1,sTerm='';
  var PS=20,af={estado:new Set(),riesgo:new Set(),entorno:new Set(),torre:new Set()};

  // F4-PERF: Cache DOM selectors (queried up to 20× per rT call)
  var $=function(id){return document.getElementById(id);};
  var $tTog=$('tTog'),$rSum=$('rSum'),$aCnt=$('aCnt'),
      $tBEq=$('tBEq'),$pIEq=$('pIEq'),$pBEq=$('pBEq'),
      $tBVu=$('tBVu'),$pIVu=$('pIVu'),$pBVu=$('pBVu'),
      $tabEq=$('tabEq'),$tabVu=$('tabVu'),
      $tabEqP=$('tabEqP'),$tabVuP=$('tabVuP'),
      $cKPI=$('cKPI'),$cAlert=$('cAlert'),
      $sIn=$('sIn'),$clBtn=$('clBtn'),$exBtn=$('exBtn'),
      $lA=$('lA'),$lO=$('lO'),
      $sQMin=$('sQMin'),$sQMax=$('sQMax'),$sAMin=$('sAMin'),$sAMax=$('sAMax'),
      $sqV=$('sqV'),$saV=$('saV'),$qFill=$('qFill'),$aFill=$('aFill');

  // Dual range init
  function initDR(mnId,mxId,fId,lId,mxVal,cbState,cbRender){
    var eMin=document.getElementById(mnId),eMax=document.getElementById(mxId),fill=document.getElementById(fId),label=document.getElementById(lId);
    var _sliderTimer=null;
    function upd(){var mn=+eMin.value,mx=+eMax.value;if(mn>mx){if(this===eMin)eMin.value=mx;else eMax.value=mn;mn=+eMin.value;mx=+eMax.value;}fill.style.left=mn/mxVal*100+'%';fill.style.width=(mx-mn)/mxVal*100+'%';label.textContent=mn+' – '+mx;cbState(mn,mx);if(_sliderTimer)clearTimeout(_sliderTimer);_sliderTimer=setTimeout(cbRender,200);}
    ['input','change'].forEach(function(e){eMin.addEventListener(e,upd);eMax.addEventListener(e,upd);});upd.call(eMin);
  }
  initDR('sQMin','sQMax','qFill','sqV',maxQSlider,function(mn,mx){tQMin=mn;tQMax=mx;pgEq=pgVu=1;},function(){rT();});
  initDR('sAMin','sAMax','aFill','saV',maxAD,function(mn,mx){tAMin=mn;tAMax=mx;pgEq=pgVu=1;},function(){rT();});

  function bc(id,grp,items){
    var el=document.getElementById(id);
    items.forEach(function(it){
      var b=document.createElement('button');
      b.className='fc';
      b.innerHTML=(it.iconHTML ? it.iconHTML : '<span class="material-icons-round" style="font-size:16px">'+it.icon+'</span>')+' <span style="margin-left:2px">'+it.label+'</span>'+(it.count!=null?' <span class="cc2">('+it.count+')</span>':'');
      if(it.style)Object.assign(b.style,it.style);
      b.addEventListener('click',function(){
        if(af[grp].has(it.val)){af[grp].delete(it.val);b.classList.remove('active');}
        else{af[grp].add(it.val);b.classList.add('active');}
        pgEq=pgVu=1;uUI();rT();
      });
      el.appendChild(b);
    });
  }
  
  bc('fEst','estado',[{val:'HABILITADO',icon:'check_circle',label:'Hab.',count:hab.length},{val:'DESHABILITADO',icon:'cancel',label:'Deshab.',count:des.length},{val:'SIN ESTADO',icon:'help_outline',label:'Sin Est.',count:sin.length}]);
  bc('fRsk','riesgo',[{val:'ok',icon:'verified',label:'OK'},{val:'atencion',icon:'info',label:'Atención'},{val:'critico',icon:'warning',label:'Crítico',style:{borderColor:'var(--err)',color:'var(--err)'}}]);
  bc('fEnt','entorno',ents.map(function(e){return{val:e[0],iconHTML:getEnvIcon(e[0]),label:e[0],count:e[1]};}));

  function gR(d){if(d.estadoAD==='HABILITADO'&&d.diasQualys>15&&d.diasLogon>15)return 'critico';if(d.diasQualys>15||d.diasLogon>15)return 'atencion';return 'ok';}
  function inRange(d){var qIn=d.diasQualys>=tQMin&&d.diasQualys<=tQMax,aIn=d.diasLogon>=tAMin&&d.diasLogon<=tAMax;return fLg==='AND'?qIn&&aIn:qIn||aIn;}

  function uCom(){
    var hQ=hab.filter(function(d){return d.diasQualys>15;}),hA=hab.filter(function(d){return d.diasLogon>15;}),hB=hab.filter(function(d){return d.diasQualys>15&&d.diasLogon>15;}),hOK=hab.filter(function(d){return d.diasQualys<=15&&d.diasLogon<=15;});
    var oQ=hQ.length-hB.length,oA=hA.length-hB.length;
    $cKPI.innerHTML='<div class="kc ok"><div class="kl">✅ Cumplen</div><div class="kv" style="color:var(--ok)">'+hOK.length+'</div><div class="ks">'+(hab.length?(hOK.length/hab.length*100).toFixed(1):'0')+'%</div></div><div class="kc wa"><div class="kl">Solo +15d Q</div><div class="kv" style="color:var(--warn)">'+oQ+'</div></div><div class="kc pu"><div class="kl">Solo +15d AD</div><div class="kv" style="color:var(--pu)">'+oA+'</div></div><div class="kc er"><div class="kl">⚠ Ambos</div><div class="kv" style="color:var(--err)">'+hB.length+'</div></div>';
    $cAlert.innerHTML=hB.length?'<div class="ac" style="margin-top:8px"><span class="material-icons-round">warning</span><div><h3>Críticos: +15d Q Y +15d AD</h3><p>'+hB.length+' equipos superan ambos.</p></div><div class="cnt">'+hB.length+'</div></div>':'<div class="sc" style="margin-top:8px"><span class="material-icons-round">verified</span><div><h3>Sin críticos</h3><p>Ninguno supera ambos umbrales.</p></div><div class="cnt">0</div></div>';
    svgDonut('dCum',[{label:'OK',value:hOK.length,color:'#1a7a32'},{label:'Solo Q',value:oQ,color:'#FFAE41'},{label:'Solo AD',value:oA,color:'#004AAC'},{label:'Ambos',value:hB.length,color:'#D14600'}],hab.length,'Habilitados');
  }
  function uUI(){var c=af.estado.size+af.riesgo.size+af.entorno.size+af.torre.size;$aCnt.style.display=c?'inline':'none';$aCnt.textContent=c;}
  function gFH(){var d=[...hosts];if(sTerm)d=d.filter(function(r){return r.hostname.toLowerCase().includes(sTerm);});if(af.estado.size)d=d.filter(function(r){return af.estado.has(r.estadoAD);});if(af.riesgo.size)d=d.filter(function(r){return af.riesgo.has(gR(r));});if(af.entorno.size)d=d.filter(function(r){return af.entorno.has(r.entorno);});if(af.torre.size)d=d.filter(function(r){return af.torre.has(r.torre||'Sin clasificar');});
    if($tTog&&$tTog.checked)d=d.filter(function(r){return inRange(r);});
    d.sort(function(a,b){var va=a[sEq.key],vb=b[sEq.key];if(typeof va==='string'){va=(va||'').toLowerCase();vb=(vb||'').toLowerCase();}return va<vb?(sEq.dir==='asc'?-1:1):va>vb?(sEq.dir==='asc'?1:-1):0;});return d;}
  function gFV(){var d=[...raw];if(sTerm)d=d.filter(function(r){return (r.hostname+' '+r.vulnName).toLowerCase().includes(sTerm);});if(af.estado.size)d=d.filter(function(r){return af.estado.has(r.estadoAD);});if(af.riesgo.size)d=d.filter(function(r){return af.riesgo.has(gR(r));});if(af.entorno.size)d=d.filter(function(r){return af.entorno.has(r.entorno);});if(af.torre.size)d=d.filter(function(r){return af.torre.has(r.torre||'Sin clasificar');});
    if($tTog&&$tTog.checked)d=d.filter(function(r){return inRange(r);});
    d.sort(function(a,b){var va=a[sVu.key],vb=b[sVu.key];if(typeof va==='string'){va=(va||'').toLowerCase();vb=(vb||'').toLowerCase();}return va<vb?(sVu.dir==='asc'?-1:1):va>vb?(sVu.dir==='asc'?1:-1):0;});return d;}
  function bdg(c,t){return '<span class="bd '+c+'">'+t+'</span>';}
  // ── F3-PERF: Debounce helper ──
  var _chartTimer=null, _searchTimer=null;
  function _debounce(fn,ms){var t;return function(){var ctx=this,args=arguments;clearTimeout(t);t=setTimeout(function(){fn.apply(ctx,args);},ms);};}

  // Cached filtered data for charts (avoid double-compute)
  var _lastFH=null, _lastFV=null;

  // rCharts: heavy SVG redraws, called with debounce
  // F2-PERF: skip if analysis panel not visible, mark dirty for tab switch
  var _chartsDirty=false;
  function rCharts(){
    var analysisPanel=document.getElementById('view-analysis');
    if(analysisPanel&&!analysisPanel.classList.contains('active')){_chartsDirty=true;return;}
    _chartsDirty=false;
    if(_lastFH) drawQuadrant(_lastFH);
    if(_lastFH) drawTopHosts(_lastFH);
    if(_lastFV) drawTreemap(_lastFV);
    if(_lastFV) drawBubble(_lastFV);
  }
  // Called when analysis tab is activated
  window._flushDirtyCharts=function(){if(_chartsDirty)rCharts();};
  // Schedule chart redraw with debounce (300ms)
  function _scheduleCharts(){
    if(_chartTimer) clearTimeout(_chartTimer);
    _chartTimer=setTimeout(function(){requestAnimationFrame(rCharts);},300);
  }
  // Immediate chart draw (for initial load / hard reset)
  function _drawChartsNow(){
    if(_chartTimer){clearTimeout(_chartTimer);_chartTimer=null;}
    rCharts();
  }

  function rT(skipCharts){
    var fH=gFH(),fV=gFV(),tAc=$tTog&&$tTog.checked,fAc=af.estado.size+af.riesgo.size+af.entorno.size+af.torre.size;
    // Cache filtered data for deferred chart use
    _lastFH=fH; _lastFV=fV;
    if(fAc||sTerm||tAc){var p=[];if(tAc)p.push('Q:'+tQMin+'–'+tQMax+'d '+(fLg==='AND'?'Y':'ó')+' AD:'+tAMin+'–'+tAMax+'d');if(af.estado.size)p.push([...af.estado].join(', '));if(af.riesgo.size)p.push([...af.riesgo].map(function(r){return r==='ok'?'OK':r==='atencion'?'Atención':'Crítico';}).join(', '));if(af.entorno.size)p.push([...af.entorno].join(', '));if(af.torre.size)p.push('Torre: '+[...af.torre].join(', '));if(sTerm)p.push('"'+sTerm+'"');
      $rSum.innerHTML='<span class="material-icons-round" style="font-size:13px">filter_list</span> <strong>'+fH.length+'</strong> equipos / <strong>'+fV.length+'</strong> vulns — '+p.join(' · ');}else $rSum.innerHTML='';
    var tpE=Math.max(1,Math.ceil(fH.length/PS));if(pgEq>tpE)pgEq=tpE;var sE=(pgEq-1)*PS,phE=fH.slice(sE,sE+PS);
    $tBEq.innerHTML=phE.map(function(d){var eb=d.estadoAD==='HABILITADO'?'bok':d.estadoAD==='DESHABILITADO'?'ber':'bof';var qb=d.diasQualys>15?'ber':d.diasQualys>7?'bwa':'bok';var ab=d.diasLogon>15?'ber':d.diasLogon>7?'bwa':'bok';var agb=d.diasAbierta>30?'ber':d.diasAbierta>15?'bwa':'bok';var rv=gR(d),rk=rv==='critico'?bdg('ber','⚠ CRÍTICO'):rv==='atencion'?bdg('bwa','ATENCIÓN'):bdg('bok','OK');
      var torre=d.torre||'Sin clasificar';var tb=torre==='Sin clasificar'?'bof':'bok';
      return '<tr class="clickable" onclick="openHostModal(\''+d.hostname+'\')"><td style="font-weight:500">'+d.hostname+'</td><td><span style="display:inline-flex;align-items:center;gap:3px">'+getEnvIcon(d.entorno)+bdg('bof',d.entorno)+'</span></td><td>'+bdg(tb,torre)+'</td><td>'+bdg(qb,d.diasQualys+'d')+'</td><td>'+bdg(agb,d.diasAbierta+'d')+'</td><td>'+bdg(eb,d.estadoAD)+'</td><td>'+bdg(ab,d.diasLogon+'d')+'</td><td style="font-family:var(--fd);font-weight:700">'+d.vc+'</td><td>'+rk+'</td></tr>';}).join('');
    $pIEq.textContent=fH.length?(sE+1)+'–'+Math.min(sE+PS,fH.length)+' de '+fH.length:'Sin resultados';pag($pBEq,pgEq,tpE,'E');
    var tpV=Math.max(1,Math.ceil(fV.length/PS));if(pgVu>tpV)pgVu=tpV;var sV=(pgVu-1)*PS,phV=fV.slice(sV,sV+PS);
    $tBVu.innerHTML=phV.map(function(d){var eb=d.estadoAD==='HABILITADO'?'bok':d.estadoAD==='DESHABILITADO'?'ber':'bof';var qb=d.diasQualys>15?'ber':d.diasQualys>7?'bwa':'bok';var ab=d.diasLogon>15?'ber':d.diasLogon>7?'bwa':'bok';var agb=(d.diasAbierta||0)>30?'ber':(d.diasAbierta||0)>15?'bwa':'bok';var rv=gR(d),rk=rv==='critico'?bdg('ber','⚠ CRÍTICO'):rv==='atencion'?bdg('bwa','ATENCIÓN'):bdg('bok','OK');var kb=d.isKEV?'<span class="kev-badge"><span class="material-icons-round">shield</span>KEV</span>':'';
      var kevCell=d.isKEV?'<td><span class="kev-badge"><span class="material-icons-round">shield</span>KEV</span></td>':'<td style="color:var(--t2);font-size:.65rem">—</td>';
      var torre=d.torre||'Sin clasificar';var tb=torre==='Sin clasificar'?'bof':'bok';
      return '<tr'+(d.isKEV?' style="background:rgba(124,58,237,.04)"':'')+'><td title="'+d.vulnName+'" style="max-width:220px;overflow:hidden;text-overflow:ellipsis">'+d.vulnName+'</td><td style="font-weight:500">'+d.hostname+'</td><td><span style="display:inline-flex;align-items:center;gap:3px">'+getEnvIcon(d.entorno)+bdg('bof',d.entorno)+'</span></td><td>'+bdg(tb,torre)+'</td><td>'+bdg(qb,d.diasQualys+'d')+'</td><td>'+bdg(agb,(d.diasAbierta||0)+'d')+'</td><td>'+bdg(eb,d.estadoAD)+'</td><td>'+bdg(ab,d.diasLogon+'d')+'</td><td>'+rk+'</td>'+kevCell+'</tr>';}).join('');
    $pIVu.textContent=fV.length?(sV+1)+'–'+Math.min(sV+PS,fV.length)+' de '+fV.length:'Sin resultados';pag($pBVu,pgVu,tpV,'V');
    $tabEq.textContent='Equipos ('+fH.length+')';$tabVu.textContent='Vulnerabilidades ('+fV.length+')';
    // F3-PERF: skipCharts===true → no charts (pagination/sort)
    //          skipCharts===false → immediate charts (initial load/reset)
    //          undefined → debounced charts (filter/search interactions)
    if(skipCharts===true){/* noop */}else if(skipCharts===false){_drawChartsNow();}else{_scheduleCharts();}
  }
  function pag(el,cur,tot,t){var bt='<button onclick="window._gp(\''+t+'\','+(cur-1)+')" '+(cur===1?'disabled':'')+'><span class="material-icons-round" style="font-size:14px">chevron_left</span></button>';var sp=Math.max(1,cur-3),ep=Math.min(tot,sp+6);if(ep-sp<6)sp=Math.max(1,ep-6);for(var i=sp;i<=ep;i++)bt+='<button onclick="window._gp(\''+t+'\','+i+')" class="'+(i===cur?'active':'')+'">'+ i+'</button>';bt+='<button onclick="window._gp(\''+t+'\','+(cur+1)+')" '+(cur===tot?'disabled':'')+'><span class="material-icons-round" style="font-size:14px">chevron_right</span></button>';el.innerHTML=bt;}
  window._gp=function(t,p){if(t==='E')pgEq=p;else pgVu=p;rT(true);};
  window._setGlobalEnv=function(v){af.entorno.clear();if(v)af.entorno.add(v);pgEq=pgVu=1;uUI();rT();};
  window._setGlobalTower=function(v){af.torre.clear();if(v)af.torre.add(v);pgEq=pgVu=1;uUI();rT();};

  $tTog.addEventListener('change',function(){pgEq=pgVu=1;rT();});
  $lA.addEventListener('click',function(){fLg='AND';$lA.classList.add('active');$lO.classList.remove('active');pgEq=pgVu=1;rT();});
  $lO.addEventListener('click',function(){fLg='OR';$lO.classList.add('active');$lA.classList.remove('active');pgEq=pgVu=1;rT();});
  $sIn.addEventListener('input',function(e){sTerm=e.target.value.toLowerCase();pgEq=pgVu=1;if(_searchTimer)clearTimeout(_searchTimer);_searchTimer=setTimeout(function(){rT();},300);});
  $clBtn.addEventListener('click',function(){Object.values(af).forEach(function(s){s.clear();});document.querySelectorAll('.fc').forEach(function(c){c.classList.remove('active');});$sIn.value='';sTerm='';$sQMin.value=0;$sQMax.value=maxQSlider;$sAMin.value=0;$sAMax.value=maxAD;tQMin=0;tQMax=maxQSlider;tAMin=0;tAMax=maxAD;$sqV.textContent='0 – '+maxQSlider;$saV.textContent='0 – '+maxAD;$qFill.style.left='0%';$qFill.style.width='100%';$aFill.style.left='0%';$aFill.style.width='100%';$tTog.checked=false;fLg='AND';$lA.classList.add('active');$lO.classList.remove('active');pgEq=pgVu=1;uUI();uCom();rT(false);});
  $exBtn.addEventListener('click',function(){
    if(curTab==='eq'){var f=gFH();var c='Hostname;Entorno;Torre;Dias Qualys;Estado AD;Dias Logon;Vulns;Riesgo\n';f.forEach(function(d){c+=d.hostname+';'+d.entorno+';'+(d.torre||'Sin clasificar')+';'+d.diasQualys+';'+d.estadoAD+';'+d.diasLogon+';'+d.vc+';'+gR(d).toUpperCase()+'\n';});dl(c,'equipos');}
    else{var f=gFV();var c='Vulnerabilidad;Hostname;Entorno;Torre;Dias Qualys;Estado AD;Dias Logon;Riesgo\n';f.forEach(function(d){c+=d.vulnName+';'+d.hostname+';'+d.entorno+';'+(d.torre||'Sin clasificar')+';'+d.diasQualys+';'+d.estadoAD+';'+d.diasLogon+';'+gR(d).toUpperCase()+'\n';});dl(c,'vulns');}});
  function dl(csv,type){var b=new Blob([csv],{type:'text/csv'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='vuln_'+type+'_'+new Date().toISOString().slice(0,10)+'.csv';a.click();}
  $tabEq.addEventListener('click',function(){curTab='eq';$tabEq.classList.add('active');$tabVu.classList.remove('active');$tabEqP.classList.add('active');$tabVuP.classList.remove('active');});
  $tabVu.addEventListener('click',function(){curTab='vu';$tabVu.classList.add('active');$tabEq.classList.remove('active');$tabVuP.classList.add('active');$tabEqP.classList.remove('active');});
  document.querySelectorAll('th[data-key]').forEach(function(th){th.addEventListener('click',function(){var k=th.dataset.key,isV=th.dataset.t==='v';var s=isV?sVu:sEq;if(s.key===k)s.dir=s.dir==='asc'?'desc':'asc';else{s.key=k;s.dir='asc';}rT(true);});});
  uCom();rT(false);

  // ── KEV: render cuando el catálogo esté listo ──────────────────────────────
  function renderKEV(){
    var banner = document.getElementById('zdBanner');
    var kpiVal = document.getElementById('kevKPIval');
    var kpiSub = document.getElementById('kevKPIsub');
    var st = window._kevStatus;

    // Si el usuario no ha subido el fichero KEV todavía
    if(!st){
      if(kpiVal) kpiVal.innerHTML = '<span style="font-size:.72rem;color:var(--t2)">No cargado</span>';
      if(kpiSub) kpiSub.innerHTML = '<span style="font-size:.65rem;color:var(--t2)">Sube el JSON de CISA en la pantalla de inicio</span>';
      if(banner) banner.innerHTML = '<div style="display:flex;align-items:center;gap:10px;padding:12px 16px;background:rgba(124,58,237,.06);border:1px dashed rgba(124,58,237,.3);border-radius:var(--r);margin-bottom:8px;font-size:.78rem;color:var(--t2)"><span class="material-icons-round" style="color:#7c3aed;flex-shrink:0">shield</span><div>Para activar la detección de vulnerabilidades explotadas activamente (CISA KEV), descarga el catálogo en <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" style="color:#7c3aed">cisa.gov</a> y súbelo junto con tu CSV la próxima vez que cargues datos.</div></div>';
      return;
    }

    // F7-PERF: Use cached KEV data from stampKEV() instead of re-scanning all rows
    // Re-stamp in case catalog arrived after initial buildDash
    window.stampKEV();
    var kevVulns = window._kevVulnsCache || [];
    var kevHostSet = window._kevHostSetCache || new Set();

    // Actualizar KPI
    if(kpiVal){ kpiVal.textContent = kevVulns.length; }
    if(kpiSub){ kpiSub.innerHTML = kevHostSet.size + ' equipos afectados<br><span style="font-size:.60rem;color:var(--t2)">✅ Catálogo: '+st.checked+' entradas · v'+(st.catalogVersion||'')+'</span>'; }

    if(!banner) return;
    if(kevVulns.length === 0){
      banner.innerHTML = '<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--okc);border-radius:var(--r);margin-bottom:8px;font-size:.78rem;color:var(--ok);border:1px solid rgba(26,122,50,.15)"><span class="material-icons-round" style="font-size:18px">verified_user</span><div><strong>Parque limpio de KEV</strong> — Ninguna vulnerabilidad del parque figura en el catálogo CISA KEV ('+st.checked+' entradas · v'+(st.catalogVersion||'')+').</div></div>';
      // Update tab badge
      var kb=document.getElementById('kevTabBadge'); if(kb) kb.style.display='none';
      return;
    }

    // ── Zero Day detection ────────────────────────────────────────────────────
    function daysBetween(d1,d2){
      if(!d1||!d2) return null;
      try{ return Math.abs(Math.round((new Date(d1)-new Date(d2))/864e5)); }catch(e){return null;}
    }
    var zdCount=0;
    kevVulns.forEach(function(e){
      var name=e[0],v=e[1];
      var kevCveArr=[...v.kevCves];
      var kevInfo={};
      kevCveArr.forEach(function(c){var i=window._kevMap[c];if(i&&(!kevInfo.dateAdded||i.dateAdded<kevInfo.dateAdded))kevInfo=i||{};});
      var pubDate=null;
      raw.forEach(function(r){if(r.vulnName===name&&r.fechaPub&&!pubDate)pubDate=r.fechaPub.split(' ')[0];});
      var gapDays=kevInfo.dateAdded?daysBetween(pubDate,kevInfo.dateAdded):null;
      var rawG = gapDays;
      e[1]._isZeroDay = rawG!==null && rawG===0;
      e[1]._isNDay    = rawG!==null && rawG>=1 && rawG<=14;
      e[1]._gapDays   = rawG!==null ? Math.abs(rawG) : null;
      e[1]._kevInfo   = kevInfo;
      if(e[1]._isZeroDay && e[1]._epss!==null && e[1]._epss>=0.3) zdCount++;
    });

    // Store globally for KEV panel
    window._kevVulns = kevVulns;
    window._kevHostSet = kevHostSet;
    window._kevZdCount = zdCount;

    // Update KEV tab badge
    var kb=document.getElementById('kevTabBadge');
    if(kb){kb.style.display='inline';kb.textContent=kevVulns.length;}

    // Dashboard banner — compact summary, link to KEV tab
    var zdHtml = zdCount>0
      ? '<span style="margin-left:10px;background:var(--errc);color:var(--err);border:1px solid rgba(209,70,0,.3);border-radius:6px;padding:2px 8px;font-size:.68rem;font-weight:700">⚡ '+zdCount+' Zero Day'+(zdCount>1?'s':'')+'</span>'
      : '';
    var ransomCount=kevVulns.filter(function(e){return e[1]._kevInfo&&e[1]._kevInfo.ransomware==='Known';}).length;
    var ransomHtml=ransomCount>0
      ? '<span style="margin-left:6px;background:var(--warnc);color:#7c4d00;border-radius:6px;padding:2px 8px;font-size:.68rem;font-weight:700">🔒 '+ransomCount+' Ransomware</span>'
      : '';
    banner.innerHTML=
      '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;padding:12px 16px;background:rgba(124,58,237,.06);border:1px solid rgba(124,58,237,.25);border-radius:var(--r);margin-bottom:8px;cursor:pointer" onclick="window._goKEVTab()">'
      +'<div style="display:flex;align-items:center;gap:8px">'
      +'<span class="material-icons-round" style="color:#7c3aed;font-size:20px">shield</span>'
      +'<div>'
      +'<div style="font-family:var(--fd);font-size:.82rem;font-weight:600;color:#7c3aed">'+kevVulns.length+' vulnerabilidades en catálogo CISA KEV — '+kevHostSet.size+' equipos afectados'+zdHtml+ransomHtml+'</div>'
      +'<div style="font-size:.68rem;color:var(--t2);margin-top:1px">Ver detalle completo, equipos afectados y filtros en el panel CISA KEV →</div>'
      +'</div></div>'
      +'</div>';

    // Update KPI card
    if(kpiVal) kpiVal.textContent=kevVulns.length;
    if(kpiSub) kpiSub.innerHTML=kevHostSet.size+' equipos'+(zdCount>0?' · <span style="color:var(--err);font-weight:700">'+zdCount+' ZD</span>':'')
      +'<br><span style="font-size:.60rem;color:var(--t2)">✅ '+st.checked+' entradas · v'+(st.catalogVersion||'')+'</span>';

    // If KEV panel is open, refresh it
    var ctKev=document.getElementById('ct-kev');
    if(ctKev&&ctKev.style.display!=='none'&&window.renderKEVPanel) window.renderKEVPanel();

  }

  // Intentar renderizar inmediatamente; si el catálogo aún carga, reintentar
  window._goKEVTab=function(){var t=document.querySelector('[data-view=kev]');if(t)t.click();};
  window._goSCCMTab=function(){var t=document.querySelector('[data-view=sccm]');if(t)t.click();};
  window._kevToggle=function(idx){
    var d=document.getElementById('kev-detail-'+idx);
    var i=document.getElementById('kev-ico-'+idx);
    if(!d)return;
    var open=d.style.display==='none';
    d.style.display=open?'block':'none';
    if(i)i.style.transform=open?'rotate(180deg)':'';
  };

  window.tryRenderKEV = function tryRenderKEV(attempts){
    if(window._kevSet !== null){
      renderKEV();
      return;
    }
    if((attempts||0)>30) return;
    setTimeout(function(){ tryRenderKEV((attempts||0)+1); }, 500);
  }
  tryRenderKEV();
}



// ══════════════════════════════════════════════════════════════════════════════
// COMPARADOR VISUAL — Diff entre dos snapshots
// ══════════════════════════════════════════════════════════════════════════════
window._openComparator = function(){
  if(pfOrder.length < 2){ alert('Necesitas al menos 2 ficheros cargados para comparar.'); return; }
  var body = '<div style="margin-bottom:16px">';
  body += '<div style="font-size:.78rem;color:var(--t2);margin-bottom:14px">Selecciona dos snapshots para ver las diferencias host por host.</div>';
  body += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">';
  body += '<div><label style="font-family:var(--fd);font-size:.72rem;font-weight:500;color:var(--t2);display:block;margin-bottom:4px">ANTES (referencia)</label>';
  body += '<select id="cmpA" style="width:100%;padding:8px 10px;border:1.5px solid var(--ol);border-radius:8px;font-family:var(--fd);font-size:.78rem;background:var(--s1);color:var(--t)">';
  pfOrder.forEach(function(n,i){ body += '<option value="'+i+'"'+(i===0?' selected':'')+'>'+n+'</option>'; });
  body += '</select></div>';
  body += '<div><label style="font-family:var(--fd);font-size:.72rem;font-weight:500;color:var(--t2);display:block;margin-bottom:4px">DESPUÉS (actual)</label>';
  body += '<select id="cmpB" style="width:100%;padding:8px 10px;border:1.5px solid var(--ol);border-radius:8px;font-family:var(--fd);font-size:.78rem;background:var(--s1);color:var(--t)">';
  pfOrder.forEach(function(n,i){ body += '<option value="'+i+'"'+(i===pfOrder.length-1?' selected':'')+'>'+n+'</option>'; });
  body += '</select></div></div>';
  body += '<button onclick="window._runComparator()" style="width:100%;padding:10px;border-radius:20px;border:none;background:var(--p);color:#fff;font-family:var(--fd);font-size:.85rem;font-weight:500;cursor:pointer">Comparar</button></div>';
  document.getElementById('modalHostname').textContent = 'Comparador de Snapshots';
  document.querySelector('#hostModal .modal-header .material-icons-round').textContent = 'compare_arrows';
  document.querySelector('#hostModal .modal-header .material-icons-round').style.color = 'var(--p)';
  document.getElementById('modalBody').innerHTML = body;
  document.getElementById('hostModal').classList.add('open');
};

window._runComparator = function(){
  var idxA = parseInt(document.getElementById('cmpA').value);
  var idxB = parseInt(document.getElementById('cmpB').value);
  var fA = pf.get(pfOrder[idxA]), fB = pf.get(pfOrder[idxB]);
  if(!fA || !fB){ alert('Fichero no encontrado'); return; }
  var hmA = {}, hmB = {};
  fA.rows.forEach(function(r){ if(!hmA[r.hostname]) hmA[r.hostname]={vc:0,vulns:new Set()}; hmA[r.hostname].vc++; hmA[r.hostname].vulns.add(r.vulnName); });
  fB.rows.forEach(function(r){ if(!hmB[r.hostname]) hmB[r.hostname]={vc:0,vulns:new Set()}; hmB[r.hostname].vc++; hmB[r.hostname].vulns.add(r.vulnName); });
  var allHosts = new Set([...Object.keys(hmA), ...Object.keys(hmB)]);
  var nuevos=[], resueltos=[], mejorados=[], empeorados=[], sinCambio=0;
  allHosts.forEach(function(h){
    var a = hmA[h], b = hmB[h];
    if(!a && b) nuevos.push({h:h, vc:b.vc});
    else if(a && !b) resueltos.push({h:h, vc:a.vc});
    else if(a && b){
      var diff = b.vc - a.vc;
      if(diff > 0) empeorados.push({h:h, antes:a.vc, despues:b.vc, diff:diff});
      else if(diff < 0) mejorados.push({h:h, antes:a.vc, despues:b.vc, diff:diff});
      else sinCambio++;
    }
  });
  empeorados.sort(function(a,b){return b.diff-a.diff;});
  mejorados.sort(function(a,b){return a.diff-b.diff;});

  var body = '<div>';
  body += '<div style="font-size:.72rem;color:var(--t2);margin-bottom:14px"><strong>'+pfOrder[idxA]+'</strong> → <strong>'+pfOrder[idxB]+'</strong></div>';
  // KPIs
  var deltaV = fB.rows.length - fA.rows.length;
  var deltaH = Object.keys(hmB).length - Object.keys(hmA).length;
  body += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin-bottom:14px">';
  body += '<div style="background:var(--errc);border-radius:10px;padding:10px;text-align:center"><div style="font-family:var(--fd);font-weight:700;font-size:1.2rem;color:var(--err)">'+nuevos.length+'</div><div style="font-size:.60rem;color:var(--t2)">Nuevos</div></div>';
  body += '<div style="background:var(--okc);border-radius:10px;padding:10px;text-align:center"><div style="font-family:var(--fd);font-weight:700;font-size:1.2rem;color:var(--ok)">'+resueltos.length+'</div><div style="font-size:.60rem;color:var(--t2)">Resueltos</div></div>';
  body += '<div style="background:var(--errc);border-radius:10px;padding:10px;text-align:center"><div style="font-family:var(--fd);font-weight:700;font-size:1.2rem;color:var(--err)">'+empeorados.length+'</div><div style="font-size:.60rem;color:var(--t2)">Empeorados</div></div>';
  body += '<div style="background:var(--okc);border-radius:10px;padding:10px;text-align:center"><div style="font-family:var(--fd);font-weight:700;font-size:1.2rem;color:var(--ok)">'+mejorados.length+'</div><div style="font-size:.60rem;color:var(--t2)">Mejorados</div></div>';
  body += '<div style="background:var(--s2);border-radius:10px;padding:10px;text-align:center"><div style="font-family:var(--fd);font-weight:700;font-size:1.2rem">'+sinCambio+'</div><div style="font-size:.60rem;color:var(--t2)">Iguales</div></div>';
  body += '</div>';
  // Delta
  body += '<div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">';
  body += '<span style="padding:6px 12px;border-radius:8px;font-size:.75rem;background:'+(deltaV<=0?'var(--okc)':'var(--errc)')+';color:'+(deltaV<=0?'var(--ok)':'var(--err)')+'"><strong>'+(deltaV>0?'+':'')+deltaV+'</strong> vulns</span>';
  body += '<span style="padding:6px 12px;border-radius:8px;font-size:.75rem;background:'+(deltaH<=0?'var(--okc)':'var(--errc)')+';color:'+(deltaH<=0?'var(--ok)':'var(--err)')+'"><strong>'+(deltaH>0?'+':'')+deltaH+'</strong> hosts</span></div>';

  function mkList(title, icon, col, items, detail){
    if(!items.length) return '';
    var h = '<h3 style="font-family:var(--fd);font-size:.80rem;font-weight:500;margin:10px 0 6px;display:flex;align-items:center;gap:6px;color:'+col+'"><span class="material-icons-round" style="font-size:16px">'+icon+'</span>'+title+' ('+items.length+')</h3>';
    h += '<ul class="modal-vuln-list" style="max-height:180px;overflow-y:auto;border:1px solid var(--olv);border-radius:8px">';
    items.slice(0,40).forEach(function(it){
      var d = '';
      if(detail==='n') d='<span class="bd ber" style="margin-left:auto">'+it.vc+' vulns</span>';
      if(detail==='w') d='<span class="bd ber" style="margin-left:auto">'+it.antes+'→'+it.despues+'</span>';
      if(detail==='b') d='<span class="bd bok" style="margin-left:auto">'+it.antes+'→'+it.despues+'</span>';
      h += '<li style="cursor:pointer" onclick="openHostModal(\''+it.h+'\')" onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'"><span class="material-icons-round" style="color:'+col+';font-size:14px">dns</span><span style="flex:1;font-weight:500;margin-left:4px;font-size:.73rem">'+it.h+'</span>'+d+'</li>';
    });
    if(items.length>40) h += '<li style="color:var(--t2);font-size:.72rem;text-align:center">+'+(items.length-40)+' más</li>';
    h += '</ul>'; return h;
  }
  body += mkList('Empeorados','trending_up','var(--err)',empeorados,'w');
  body += mkList('Nuevos','fiber_new','var(--err)',nuevos,'n');
  body += mkList('Mejorados','trending_down','var(--ok)',mejorados,'b');
  body += mkList('Resueltos','check_circle','var(--ok)',resueltos,'');
  body += '</div>';
  document.getElementById('modalHostname').textContent = pfOrder[idxA].substring(0,18)+' vs '+pfOrder[idxB].substring(0,18);
  document.getElementById('modalBody').innerHTML = body;
};
