// SCCM — Colecciones de despliegue
// ══════════════════════════════════════════════════════════════════════════════

var _sccmCollections = [];
var _sccmPrefix = localStorage.getItem('sccm_prefix_v1') || 'VUL-';
var SCCM_SAVED_KEY = 'sccm_saved_v1';

// ── LocalStorage helpers ──────────────────────────────────────────────────────
function sccmLoadSaved(){
  try{ return JSON.parse(localStorage.getItem(SCCM_SAVED_KEY)||'[]'); }
  catch(e){ return []; }
}
function sccmSaveSaved(arr){
  localStorage.setItem(SCCM_SAVED_KEY, JSON.stringify(arr));
}

// ── Risk helpers ──────────────────────────────────────────────────────────────
function _sccmRisk(h){
  if(h.estadoAD==='HABILITADO' && h.diasQualys>15 && h.diasLogon>15) return 'CRITICO';
  if(h.diasQualys>15 || h.diasLogon>15) return 'ALTO';
  return 'MEDIO';
}
function _sccmRiskOrder(r){ return r==='CRITICO'?0:r==='ALTO'?1:2; }

function _sccmNormSolution(sol){
  if(!sol) return '__SIN_SOLUCION__';
  var kb = sol.match(/KB\d{6,8}/i);
  if(kb) return kb[0].toUpperCase();
  return sol.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim().substring(0,80);
}

// ── Smart collection builder ─────────────────────────────────────────────────
// Agrupa por familia de producto/OS, luego selecciona el KB más reciente
// (parches de Microsoft son acumulativos: el más alto cubre todos los anteriores)

function _sccmExtractFamily(vulnName){
  var vn=(vulnName||'').toLowerCase();
  // Microsoft Windows — versión específica primero
  if(/microsoft|windows/.test(vn)){
    if(/server.{0,3}2025/.test(vn))   return {vendor:'Microsoft',family:'Windows Server 2025'};
    if(/server.{0,3}2022/.test(vn))   return {vendor:'Microsoft',family:'Windows Server 2022'};
    if(/server.{0,3}2019/.test(vn))   return {vendor:'Microsoft',family:'Windows Server 2019'};
    if(/server.{0,3}2016/.test(vn))   return {vendor:'Microsoft',family:'Windows Server 2016'};
    if(/server.{0,3}2012/.test(vn))   return {vendor:'Microsoft',family:'Windows Server 2012 R2'};
    if(/windows.{0,3}11/.test(vn))    return {vendor:'Microsoft',family:'Windows 11'};
    if(/windows.{0,3}10/.test(vn))    return {vendor:'Microsoft',family:'Windows 10'};
    if(/windows.{0,3}7/.test(vn))     return {vendor:'Microsoft',family:'Windows 7'};
    // Componentes de Windows que se parchean con el CU mensual
    if(/desktop window manager|dwm\b|http.?2|spnego|negoex|ntlm|kerberos|win32k|smb\b|rdp\b|remote desktop|print spooler|task scheduler|defender|msdt|scripting engine|jscript|vbscript|hyper-v|winsock|netlogon|dns client|cryptographic|certificate/.test(vn))
      return {vendor:'Microsoft',family:'Windows (Parche Mensual)'};
    // Parche mensual genérico — fusionado
    if(/windows security update|microsoft windows security|microsoft windows/.test(vn))
      return {vendor:'Microsoft',family:'Windows (Parche Mensual)'};
    // Office y aplicaciones del ecosistema Office
    if(/microsoft office|microsoft outlook|microsoft word|microsoft excel|microsoft powerpoint|microsoft onenote|microsoft access|microsoft publisher|microsoft visio|microsoft project/.test(vn))
      return {vendor:'Microsoft',family:'Office'};
    if(/microsoft edge/.test(vn))     return {vendor:'Microsoft',family:'Edge'};
    if(/microsoft teams/.test(vn))    return {vendor:'Microsoft',family:'Teams'};
    if(/microsoft.net|microsoft \.net|\bdotnet\b|net framework|net core/.test(vn)) return {vendor:'Microsoft',family:'.NET'};
    if(/internet explorer/.test(vn))  return {vendor:'Microsoft',family:'Internet Explorer'};
    if(/visual studio/.test(vn))      return {vendor:'Microsoft',family:'Visual Studio'};
    if(/sql server/.test(vn))         return {vendor:'Microsoft',family:'SQL Server'};
    if(/exchange server|microsoft exchange/.test(vn)) return {vendor:'Microsoft',family:'Exchange Server'};
    if(/sharepoint/.test(vn))         return {vendor:'Microsoft',family:'SharePoint'};
    // Resto de Microsoft sin clasificar específico → también va al parche mensual
    // (la mayoría son componentes del SO corregidos en el CU)
    return {vendor:'Microsoft',family:'Windows (Parche Mensual)'};
  }
  if(/7-?zip/.test(vn))                return {vendor:'7-Zip',family:'7-Zip'};
  if(/google chrome|chromium/.test(vn)) return {vendor:'Google',family:'Chrome'};
  if(/mozilla firefox|firefox/.test(vn)) return {vendor:'Mozilla',family:'Firefox'};
  if(/java se|java runtime|\bjre\b|\bjdk\b|oracle java/.test(vn)) return {vendor:'Oracle',family:'Java SE'};
  if(/acrobat reader|adobe acrobat/.test(vn)) return {vendor:'Adobe',family:'Acrobat Reader DC'};
  if(/adobe flash/.test(vn))           return {vendor:'Adobe',family:'Flash Player'};
  if(/adobe/.test(vn))                 return {vendor:'Adobe',family:'Adobe (Otros)'};
  if(/dell.{0,10}(bios|client|security|firmware)/.test(vn)) return {vendor:'Dell',family:'Dell BIOS/Firmware'};
  if(/\bdell\b/.test(vn))              return {vendor:'Dell',family:'Dell (Otros)'};
  if(/vmware/.test(vn))                return {vendor:'VMware',family:'VMware'};
  if(/cisco/.test(vn))                 return {vendor:'Cisco',family:'Cisco'};
  if(/node\.js|nodejs/.test(vn))      return {vendor:'Node.js',family:'Node.js'};
  if(/\bintel\b/.test(vn))            return {vendor:'Intel',family:'Intel Drivers/Firmware'};
  if(/\bvlc\b/.test(vn))              return {vendor:'VideoLAN',family:'VLC'};
  if(/\bzoom\b/.test(vn))             return {vendor:'Zoom',family:'Zoom'};
  if(/greenshot/.test(vn))             return {vendor:'Greenshot',family:'Greenshot'};
  if(/\bgimp\b/.test(vn))             return {vendor:'GIMP',family:'GIMP'};
  if(/\bpython\b/.test(vn))           return {vendor:'Python',family:'Python'};
  if(/openssl/.test(vn))               return {vendor:'OpenSSL',family:'OpenSSL'};
  if(/apache/.test(vn))                return {vendor:'Apache',family:'Apache HTTP Server'};
  var first=(vulnName||'').split(/\s+/)[0]||'Sin clasificar';
  return {vendor:first,family:first};
}
function _sccmExtractKBs(sol){
  if(!sol) return [];
  var kbs=(sol.match(/KB\d{6,8}/gi)||[]).map(function(k){return k.toUpperCase();});
  return [...new Set(kbs)];
}

function _sccmLatestKB(kbList){
  if(!kbList||!kbList.length) return null;
  // KB más alto por número = más reciente (para misma familia de producto)
  return kbList.slice().sort(function(a,b){
    return parseInt(b.slice(2))-parseInt(a.slice(2));
  })[0];
}

function _sccmExtractVersion(sol){
  if(!sol) return null;
  var m=sol.match(/version\s*([\d]+\.[\d]+[\.\d]*)/i)||sol.match(/([\d]+\.[\d]+\.[\d]+[\.\d]*)/);
  return m?m[1]:null;
}

function _sccmBuildCollections(){
  if(!window._raw||!window._raw.length) return [];

  // 1. Agregar hosts
  var hostMap={};
  window._raw.forEach(function(r){
    if(!r.hostname) return;
    if(!hostMap[r.hostname]) hostMap[r.hostname]={
      hostname:r.hostname,entorno:r.entorno||'',estadoAD:r.estadoAD||'SIN ESTADO',
      diasQualys:r.diasQualys||0,diasLogon:r.diasLogon||0
    };
    var h=hostMap[r.hostname];
    if(r.diasQualys>h.diasQualys) h.diasQualys=r.diasQualys;
    if(r.diasLogon>h.diasLogon)   h.diasLogon=r.diasLogon;
    if(r.entorno)                  h.entorno=r.entorno;
    if(r.estadoAD&&r.estadoAD!=='SIN ESTADO') h.estadoAD=r.estadoAD;
  });

  // 2. Agrupar por familia de producto
  var familyMap={};
  window._raw.forEach(function(r){
    var f=_sccmExtractFamily(r.vulnName);
    var key=f.vendor+'|'+f.family;
    if(!familyMap[key]) familyMap[key]={
      vendor:f.vendor, family:f.family, key:key,
      vulns:new Set(), hosts:new Set(),
      allKBs:new Set(), allSols:[], allVersions:new Set()
    };
    var g=familyMap[key];
    if(r.vulnName) g.vulns.add(r.vulnName);
    if(r.hostname) g.hosts.add(r.hostname);
    // Recopilar todos los KBs y versiones mencionados en soluciones
    var kbs=_sccmExtractKBs(r.solucion);
    kbs.forEach(function(kb){g.allKBs.add(kb);});
    var ver=_sccmExtractVersion(r.solucion);
    if(ver) g.allVersions.add(ver);
    if(r.solucion&&g.allSols.indexOf(r.solucion)<0) g.allSols.push(r.solucion);
  });

  // 3. Para cada familia: determinar la acción óptima (KB más reciente o versión más alta)
  var cols=[];
  Object.values(familyMap).forEach(function(g){
    var hosts=[...g.hosts].map(function(hn){return hostMap[hn];}).filter(Boolean);
    var risks=hosts.map(function(h){return _sccmRisk(h);});
    var topRisk=risks.includes('CRITICO')?'CRITICO':risks.includes('ALTO')?'ALTO':'MEDIO';

    // Acción óptima
    var kbList=[...g.allKBs];
    var latestKB=_sccmLatestKB(kbList);
    var latestVer=null;
    if(g.allVersions.size>0){
      var vers=[...g.allVersions].sort(function(a,b){
        var partsA=a.split('.').map(Number), partsB=b.split('.').map(Number);
        for(var i=0;i<Math.max(partsA.length,partsB.length);i++){
          var d=(partsB[i]||0)-(partsA[i]||0);
          if(d!==0) return d;
        }
        return 0;
      });
      latestVer=vers[0];
    }

    // Extraer links de descarga de las soluciones
    var downloadLinks=[];
    g.allSols.forEach(function(s){
      var hrefs=(s.match(/href=["']([^"']+)["']/gi)||[]).map(function(h){
        return h.replace(/^href=["']/i,'').replace(/["']$/,'');
      });
      hrefs.forEach(function(url){
        // Filtrar solo links relevantes (Microsoft, vendor oficial)
        if(/support\.microsoft\.com|msrc\.microsoft\.com|catalog\.update\.microsoft|docs\.microsoft|7-zip\.org|mozilla\.org|java\.com|adobe\.com|dell\.com|vmware\.com|intel\.com/.test(url)){
          if(downloadLinks.indexOf(url)<0) downloadLinks.push(url);
        }
      });
    });

    // Encontrar la solución más representativa (la que contiene el KB más reciente)
    var bestSol='';
    if(latestKB){
      g.allSols.forEach(function(s){
        if(s&&s.toUpperCase().indexOf(latestKB)>=0&&!bestSol) bestSol=s;
      });
    }
    if(!bestSol && g.allSols.length) bestSol=g.allSols[0];
    bestSol=(bestSol||'').replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim().substring(0,250);

    // Nombre de la acción
    var actionLabel;
    if(latestKB) actionLabel=latestKB+' (acumulativo — cubre '+kbList.length+' KB'+(kbList.length>1?'s':'')+')';
    else if(latestVer) actionLabel='Actualizar a versión '+latestVer;
    else actionLabel='Aplicar parche de seguridad';

    cols.push({
      vendor:g.vendor, family:g.family,
      actionLabel:actionLabel,
      latestKB:latestKB, allKBs:kbList, latestVer:latestVer,
      bestSol:bestSol, downloadLinks:downloadLinks.slice(0,6),
      vulns:[...g.vulns], hosts:hosts,
      topRisk:topRisk,
      critCount:risks.filter(function(r){return r==='CRITICO';}).length,
      altoCount:risks.filter(function(r){return r==='ALTO';}).length,
      kbCount:kbList.length
    });
  });

  // 4. Ordenar: CRITICO > ALTO > MEDIO, luego por nº equipos
  cols.sort(function(a,b){
    var rd=_sccmRiskOrder(a.topRisk)-_sccmRiskOrder(b.topRisk);
    return rd!==0?rd:b.hosts.length-a.hosts.length;
  });
  cols.forEach(function(c,i){c.id=String(i+1).padStart(3,'0');});
  return cols;
}

// ── Copy to clipboard ─────────────────────────────────────────────────────────
function _sccmCopyToClipboard(text, btnEl){
  navigator.clipboard.writeText(text).then(function(){
    var orig=btnEl.innerHTML;
    btnEl.innerHTML='<span class="material-icons-round" style="font-size:14px">check</span> ¡Copiado!';
    btnEl.style.cssText+=';background:var(--okc)!important;color:var(--ok)!important;border-color:var(--ok)!important';
    setTimeout(function(){btnEl.innerHTML=orig;btnEl.removeAttribute('style');btnEl.style.cssText='';},2000);
  });
}

// ── Export CSV ────────────────────────────────────────────────────────────────
function _sccmExportCSV(colName, hosts){
  var rows=['Hostname,Entorno,Estado AD,Dias Qualys,Dias Logon,Riesgo'];
  hosts.forEach(function(h){
    rows.push([h.hostname,h.entorno||'',h.estadoAD||'',h.diasQualys||0,h.diasLogon||0,_sccmRisk(h)].join(','));
  });
  var blob=new Blob([rows.join('\n')],{type:'text/csv'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=colName.replace(/[^a-z0-9_-]/gi,'_')+'.csv';
  a.click();
}

// ── Status badge ──────────────────────────────────────────────────────────────
function _sccmStatusBadge(st){
  if(st==='desplegada') return '<span style="background:var(--okc);color:var(--ok);border:1px solid rgba(24,128,56,.2);border-radius:6px;padding:2px 8px;font-size:.65rem;font-weight:700">✅ Desplegada</span>';
  if(st==='creada')     return '<span style="background:var(--pc);color:#041e49;border:1px solid rgba(26,115,232,.2);border-radius:6px;padding:2px 8px;font-size:.65rem;font-weight:700">✓ Creada en SCCM</span>';
  return '<span style="background:var(--warnc);color:#7c4d00;border:1px solid rgba(249,171,0,.2);border-radius:6px;padding:2px 8px;font-size:.65rem;font-weight:700">⏳ Pendiente</span>';
}

// ══════════════════════════════════════════════════════════════════════════════
// RENDER PRINCIPAL
// ══════════════════════════════════════════════════════════════════════════════
window.renderSCCMPanel = function(){
  var ct=document.getElementById('ct-sccm');
  if(!ct) return;
  if(!window._raw||!window._raw.length){
    ct.innerHTML='<div style="padding:40px;text-align:center;color:var(--t2)">Carga un CSV primero para generar colecciones.</div>';
    return;
  }

  _sccmCollections=_sccmBuildCollections();
  var saved=sccmLoadSaved();
  var totalHosts=Object.keys((function(){var m={};(window._raw||[]).forEach(function(r){if(r.hostname)m[r.hostname]=1;});return m;})()).length;

  var html='<div style="max-width:1440px;margin:0 auto;padding:24px 28px">';

  // Header
  html+='<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">'
    +'<div><div style="font-family:var(--fd);font-size:1.15rem;font-weight:700;display:flex;align-items:center;gap:10px;letter-spacing:-.3px"><span class="material-icons-round" style="color:var(--p);font-size:24px">dynamic_feed</span>Colecciones SCCM</div>'
    +'<div style="font-size:.73rem;color:var(--t2);margin-top:4px">Agrupación inteligente por familia de producto · Priorizado por riesgo · '+_sccmCollections.length+' colecciones · '+totalHosts+' hosts</div></div>'
    +'</div>';

  // ══ SECCIÓN 1: COLECCIONES GUARDADAS ═════════════════════════════════════
  html+='<div style="font-family:var(--fd);font-size:.88rem;font-weight:600;color:var(--t2);margin-bottom:12px;display:flex;align-items:center;gap:8px;text-transform:uppercase;letter-spacing:.5px">'
    +'<span class="material-icons-round" style="font-size:18px;color:var(--p)">bookmark</span>'
    +'Colecciones guardadas <span style="background:var(--p);color:#fff;font-size:.6rem;padding:2px 8px;border-radius:10px;margin-left:4px;font-weight:700">'+saved.length+'</span>'
    +'<span style="flex:1;height:1px;background:linear-gradient(90deg,var(--olv),transparent);margin-left:8px"></span>'
    +'</div>';

  if(saved.length===0){
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px 24px;margin-bottom:20px;text-align:center;color:var(--t2);font-size:.80rem">'
      +'<span class="material-icons-round" style="font-size:32px;display:block;margin-bottom:8px;opacity:.3">bookmarks</span>'
      +'Aún no has guardado ninguna colección.<br>Genera las colecciones abajo y pulsa <strong>Guardar</strong> en las que quieras conservar.'
      +'</div>';
  } else {
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);overflow:hidden;margin-bottom:20px">';
    // Cabecera tabla
    html+='<div style="display:grid;grid-template-columns:1fr 90px 80px 90px 120px 160px;gap:0;padding:8px 16px;background:var(--s2);font-size:.65rem;font-weight:500;color:var(--t2);text-transform:uppercase;letter-spacing:.3px">'
      +'<div>Nombre colección</div><div>Equipos</div><div>Riesgo</div><div>Creada</div><div>Estado</div><div>Acciones</div></div>';

    saved.forEach(function(sc, si){
      var rColor=sc.topRisk==='CRITICO'?'var(--err)':sc.topRisk==='ALTO'?'var(--warn)':'var(--p)';
      html+='<div style="display:grid;grid-template-columns:1fr 90px 80px 90px 120px 160px;gap:0;align-items:center;padding:9px 16px;border-top:1px solid var(--olv);font-size:.78rem">';
      // Nombre
      html+='<div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+sc.name+'">'+sc.name+'</div>';
      // Equipos
      html+='<div style="color:var(--t2)">'+sc.hostCount+' equipos</div>';
      // Riesgo
      html+='<div><span style="font-size:.65rem;font-weight:700;color:'+rColor+'">'+sc.topRisk+'</span></div>';
      // Fecha creación
      html+='<div style="font-size:.68rem;color:var(--t2)">'+sc.date+'</div>';
      // Estado — selector
      html+='<div><select onchange="window._sccmSetStatus('+si+',this.value)" '
        +'style="font-size:.70rem;padding:3px 6px;border:1px solid var(--ol);border-radius:6px;font-family:var(--fb);cursor:pointer;background:var(--s1)">'
        +'<option value="pendiente"'+(sc.status==='pendiente'?' selected':'')+'>⏳ Pendiente</option>'
        +'<option value="creada"'+(sc.status==='creada'?' selected':'')+'>✓ Creada SCCM</option>'
        +'<option value="desplegada"'+(sc.status==='desplegada'?' selected':'')+'>✅ Desplegada</option>'
        +'</select></div>';
      // Acciones
      html+='<div style="display:flex;gap:5px">';
      html+='<button id="sccmSavedCopy-'+si+'" onclick="window._sccmCopySaved('+si+')" '
        +'style="display:inline-flex;align-items:center;gap:3px;padding:4px 9px;border-radius:10px;border:1px solid var(--ol);background:var(--s1);font-size:.68rem;cursor:pointer">'
        +'<span class="material-icons-round" style="font-size:12px">content_copy</span> Copiar</button>';
      html+='<button onclick="window._sccmExportSaved('+si+')" '
        +'style="display:inline-flex;align-items:center;gap:3px;padding:4px 9px;border-radius:10px;border:1px solid var(--p);color:var(--p);background:transparent;font-size:.68rem;cursor:pointer">'
        +'<span class="material-icons-round" style="font-size:12px">download</span> CSV</button>';
      html+='<button onclick="window._sccmDeleteSaved('+si+')" title="Eliminar" '
        +'style="display:inline-flex;align-items:center;padding:4px 6px;border-radius:10px;border:1px solid var(--olv);background:var(--s1);color:var(--t2);font-size:.68rem;cursor:pointer">'
        +'<span class="material-icons-round" style="font-size:12px">delete_outline</span></button>';
      html+='</div>';
      html+='</div>';
    });
    html+='</div>';

    // Stats de guardadas
    var pend=saved.filter(function(s){return s.status==='pendiente';}).length;
    var crea=saved.filter(function(s){return s.status==='creada';}).length;
    var desp=saved.filter(function(s){return s.status==='desplegada';}).length;
    html+='<div style="display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap">';
    html+='<div class="kc wa"><div class="kl">⏳ Pendientes</div><div class="kv">'+pend+'</div></div>';
    html+='<div class="kc"><div class="kl">✓ Creadas SCCM</div><div class="kv">'+crea+'</div></div>';
    html+='<div class="kc ok"><div class="kl">✅ Desplegadas</div><div class="kv">'+desp+'</div></div>';
    html+='</div>';
  }

  // ══ SECCIÓN 2: COLECCIONES PROPUESTAS ════════════════════════════════════
  html+='<div style="font-family:var(--fd);font-size:.88rem;font-weight:600;color:var(--t2);margin-bottom:14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;text-transform:uppercase;letter-spacing:.5px">'
    +'<span class="material-icons-round" style="font-size:18px;color:var(--p)">auto_awesome</span>'
    +'Colecciones propuestas <span style="background:var(--p);color:#fff;font-size:.6rem;padding:2px 8px;border-radius:10px;margin-left:4px;font-weight:700">'+_sccmCollections.length+'</span>'
    +'<span style="flex:1;height:1px;background:linear-gradient(90deg,var(--olv),transparent);margin-left:8px"></span>'
    +'<div style="margin-left:auto;display:flex;gap:8px;align-items:center">'
    +'<div style="display:flex;align-items:center;gap:6px;font-size:.75rem">'
    +'<span style="color:var(--t2)">Prefijo:</span>'
    +'<input id="sccmPrefixInput" type="text" value="'+_sccmPrefix+'" '
    +'style="width:75px;padding:4px 8px;border:1.5px solid var(--ol);border-radius:6px;font-size:.78rem;font-family:var(--fb)" '
    +'oninput="window._sccmUpdatePrefix(this.value)">'
    +'</div>'
    +'<button onclick="window._sccmSaveAll()" style="display:inline-flex;align-items:center;gap:4px;padding:6px 14px;border-radius:14px;border:none;background:var(--p);color:#fff;font-family:var(--fd);font-size:.75rem;font-weight:500;cursor:pointer">'
    +'<span class="material-icons-round" style="font-size:14px">bookmark_add</span> Guardar todas</button>'
    +'<button onclick="window._sccmExportAll()" style="display:inline-flex;align-items:center;gap:4px;padding:6px 14px;border-radius:14px;border:1px solid var(--p);background:transparent;color:var(--p);font-family:var(--fd);font-size:.75rem;font-weight:500;cursor:pointer">'
    +'<span class="material-icons-round" style="font-size:14px">download</span> Exportar CSV</button>'
    +'</div></div>';

  html+='<div style="display:flex;flex-direction:column;gap:8px">';
  _sccmCollections.forEach(function(col, ci){
    var rColor=col.topRisk==='CRITICO'?'var(--err)':col.topRisk==='ALTO'?'var(--warn)':'var(--p)';
    var rBg=col.topRisk==='CRITICO'?'rgba(217,48,37,.05)':col.topRisk==='ALTO'?'rgba(249,171,0,.05)':'rgba(26,115,232,.04)';
    var colName=_sccmPrefix+(col.latestKB||col.family.replace(/\s+/g,'-').substring(0,20));

    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);overflow:hidden;border-left:4px solid '+rColor+'">';

    // Header
    html+='<div style="display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;background:'+rBg+'" onclick="window._sccmToggle('+ci+')">';
    html+='<span class="material-icons-round" style="font-size:15px;color:var(--t2);transition:transform .2s;flex-shrink:0" id="sccm-ico-'+ci+'">expand_more</span>';
    html+='<div style="flex:1;min-width:0">';
    html+='<div style="display:flex;align-items:center;gap:7px;margin-bottom:3px">';
    html+='<span style="font-size:.62rem;font-weight:700;color:'+rColor+';border:1px solid '+rColor+'30;background:'+rBg+';padding:1px 7px;border-radius:5px">'+col.topRisk+'</span>';
    html+='<span style="font-size:.68rem;color:var(--t2);font-weight:600">'+col.vendor+'</span>';
    html+='<span style="font-size:.83rem;font-weight:700;font-family:var(--fd)">'+col.family+'</span>';
    html+='</div>';
    html+='<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;flex-wrap:wrap">';
    html+='<span style="font-size:.67rem;color:var(--t2)">Acción óptima:</span>';
    if(col.latestKB){
      html+='<span style="background:rgba(26,115,232,.1);color:var(--p);border-radius:5px;padding:1px 8px;font-size:.73rem;font-weight:700">📦 '+col.latestKB+'</span>';
      if(col.kbCount>1) html+='<span style="font-size:.65rem;color:var(--ok)">✓ acumulativo — sustituye '+col.kbCount+' KBs</span>';
    } else if(col.latestVer){
      html+='<span style="background:rgba(26,115,232,.1);color:var(--p);border-radius:5px;padding:1px 8px;font-size:.73rem;font-weight:700">⬆ versión '+col.latestVer+'</span>';
    } else {
      html+='<span style="font-size:.70rem;color:var(--t2)">Aplicar parche de seguridad</span>';
    }
    html+='<input id="sccmName-'+ci+'" type="text" value="'+colName+'" onclick="event.stopPropagation()" '
      +'style="font-size:.70rem;border:1.5px dashed var(--ol);border-radius:5px;padding:1px 7px;background:transparent;width:185px;margin-left:6px;color:var(--t)" '
      +'onfocus="this.style.borderColor=\'var(--p)\';this.style.borderStyle=\'solid\'" '
      +'onblur="this.style.borderColor=\'var(--ol)\';this.style.borderStyle=\'dashed\'" '
      +'title="Nombre colección SCCM (editable)">';
    html+='</div>';
    html+='<div style="font-size:.67rem;color:var(--t2);display:flex;gap:10px;flex-wrap:wrap">';
    html+='<span style="font-weight:600;color:'+rColor+'">'+col.hosts.length+' equipos</span>';
    html+='<span>'+col.vulns.length+' vulnerabilidad'+(col.vulns.length>1?'es':'')+'</span>';
    if(col.critCount>0) html+='<span style="color:var(--err)">'+col.critCount+' críticos</span>';
    if(col.altoCount>0) html+='<span style="color:var(--warn)">'+col.altoCount+' altos</span>';
    html+='</div></div>';

    html+='<div style="display:flex;gap:5px;flex-shrink:0" onclick="event.stopPropagation()">';
    html+='<button id="sccmSaveBtn-'+ci+'" onclick="window._sccmSaveOne('+ci+')" '
      +'style="display:inline-flex;align-items:center;gap:3px;padding:5px 10px;border-radius:12px;border:none;background:var(--p);color:#fff;font-size:.70rem;font-family:var(--fd);font-weight:500;cursor:pointer">'
      +'<span class="material-icons-round" style="font-size:13px">bookmark_add</span> Guardar</button>';
    html+='<button id="sccmCopyBtn-'+ci+'" onclick="window._sccmCopyCol('+ci+')" '
      +'style="display:inline-flex;align-items:center;gap:3px;padding:5px 10px;border-radius:12px;border:1px solid var(--ol);background:var(--s1);font-size:.70rem;font-family:var(--fd);cursor:pointer">'
      +'<span class="material-icons-round" style="font-size:13px">content_copy</span> Copiar</button>';
    html+='<button onclick="window._sccmExportOne('+ci+')" '
      +'style="display:inline-flex;align-items:center;gap:3px;padding:5px 10px;border-radius:12px;border:1px solid var(--p);background:transparent;color:var(--p);font-size:.70rem;font-family:var(--fd);cursor:pointer">'
      +'<span class="material-icons-round" style="font-size:13px">download</span> CSV</button>';
    html+='</div></div>'; // end header

    // Body expandible
    html+='<div id="sccm-body-'+ci+'" style="display:none;border-top:1px solid var(--olv)">';
    if(col.bestSol&&col.bestSol!=='__SIN_SOLUCION__'){
      html+='<div style="padding:10px 16px;background:var(--s2);border-bottom:1px solid var(--olv)">';
      html+='<div style="font-size:.62rem;text-transform:uppercase;color:var(--t2);font-weight:500;margin-bottom:4px">Instrucciones de remediación</div>';
      html+='<div style="font-size:.74rem;line-height:1.5;margin-bottom:8px">'+col.bestSol+'</div>';
      // Links de descarga directa
      if(col.downloadLinks&&col.downloadLinks.length>0){
        html+='<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">';
        html+='<span style="font-size:.65rem;color:var(--t2);font-weight:500;align-self:center">🔗 Descargar:</span>';
        // Agrupar por KB si son links de Microsoft
        var shownKBs=new Set();
        col.downloadLinks.forEach(function(url){
          var kb=url.match(/help\/?(KB?\d{6,8})/i)||url.match(/(KB\d{6,8})/i);
          var kbLabel=kb?kb[1].toUpperCase():null;
          if(kbLabel&&shownKBs.has(kbLabel)) return;
          if(kbLabel) shownKBs.add(kbLabel);
          var label=kbLabel||(url.includes('msrc')?'MSRC':url.includes('docs.microsoft')?'Docs':url.includes('7-zip')?'7-Zip':url.includes('java')?'Java':'Ver');
          html+='<a href="'+url+'" target="_blank" style="display:inline-flex;align-items:center;gap:3px;padding:3px 9px;border-radius:10px;background:var(--pc);color:var(--p);font-size:.68rem;font-weight:600;text-decoration:none;border:1px solid rgba(26,115,232,.2)">'
            +'<span class="material-icons-round" style="font-size:11px">open_in_new</span>'+label+'</a>';
        });
        html+='</div>';
      }
      html+='</div>';
    }
    // Vulnerabilidades cubiertas — lista completa con nombres reales
    if(col.vulns.length>0){
      var vulnsVisible = col.vulns.length <= 5;
      html+='<div style="padding:8px 16px;border-bottom:1px solid var(--olv)">';
      html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">';
      html+='<span style="font-size:.65rem;font-weight:600;text-transform:uppercase;color:var(--t2)">Vulnerabilidades cubiertas ('+col.vulns.length+')</span>';
      if(col.vulns.length>5){
        html+='<button id="sccmVulnToggle-'+ci+'" onclick="window._sccmVulnsToggle('+ci+')" '
          +'style="display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:10px;border:1px solid var(--ol);background:var(--s1);font-size:.67rem;cursor:pointer">'
          +'<span class="material-icons-round" style="font-size:12px">expand_more</span> Ver todas</button>';
      }
      html+='</div>';
      // Lista de vulns — siempre visible las primeras 5, resto colapsadas
      html+='<div id="sccmVulnList-'+ci+'" style="display:flex;flex-direction:column;gap:3px">';
      col.vulns.forEach(function(v, vi){
        var hidden = vi >= 5 ? 'style="display:none"' : '';
        html+='<div class="sccm-vuln-row-'+ci+'" '+hidden+' style="display:flex;align-items:center;gap:6px;padding:3px 6px;border-radius:5px;background:var(--s2)">'
          +'<span class="material-icons-round" style="font-size:11px;color:var(--t2);flex-shrink:0">bug_report</span>'
          +'<span style="font-size:.73rem;line-height:1.35;color:var(--t)">'+v+'</span>'
          +'</div>';
      });
      html+='</div>';
      html+='</div>';
    }
    // Tabla de equipos
    html+='<div style="padding:10px 16px">';
    html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">';
    html+='<span style="font-size:.70rem;font-weight:600;color:var(--t2)">EQUIPOS ('+col.hosts.length+')</span>';
    html+='<div style="flex:1;display:flex;align-items:center;gap:4px;background:var(--s2);border:1px solid var(--ol);border-radius:14px;padding:3px 10px;max-width:260px">'
      +'<span class="material-icons-round" style="font-size:13px;color:var(--t2)">search</span>'
      +'<input type="text" placeholder="Filtrar equipos..." style="border:none;outline:none;background:none;font-size:.72rem;width:100%" '
      +'oninput="window._sccmFilter('+ci+',this.value)"></div>';
    html+='<button onclick="window._sccmToggleAll('+ci+',true)" style="padding:3px 8px;border-radius:10px;border:1px solid var(--ol);background:var(--s1);font-size:.68rem;cursor:pointer">✓ Todos</button>';
    html+='<button onclick="window._sccmToggleAll('+ci+',false)" style="padding:3px 8px;border-radius:10px;border:1px solid var(--ol);background:var(--s1);font-size:.68rem;cursor:pointer">✗ Ninguno</button>';
    html+='</div>';
    html+='<div style="max-height:260px;overflow-y:auto;border:1px solid var(--olv);border-radius:8px">';
    html+='<table style="width:100%;border-collapse:collapse;font-size:.73rem"><thead style="background:var(--s2);position:sticky;top:0"><tr>'
      +'<th style="padding:5px 10px;width:28px"><input type="checkbox" id="sccmAllChk-'+ci+'" checked onchange="window._sccmToggleAll('+ci+',this.checked)" style="accent-color:var(--p)"></th>'
      +'<th style="padding:5px 10px;text-align:left;font-weight:500;color:var(--t2)">Hostname</th>'
      +'<th style="padding:5px 10px;text-align:left;font-weight:500;color:var(--t2)">Entorno</th>'
      +'<th style="padding:5px 10px;text-align:left;font-weight:500;color:var(--t2)">Estado AD</th>'
      +'<th style="padding:5px 10px;text-align:left;font-weight:500;color:var(--t2)">Días Q</th>'
      +'<th style="padding:5px 10px;text-align:left;font-weight:500;color:var(--t2)">Riesgo</th>'
      +'</tr></thead><tbody id="sccm-tbody-'+ci+'">';
    col.hosts.forEach(function(h,hi){
      var risk=_sccmRisk(h);
      var rC=risk==='CRITICO'?'var(--err)':risk==='ALTO'?'var(--warn)':'var(--ok)';
      var adC=h.estadoAD==='HABILITADO'?'bok':h.estadoAD==='DESHABILITADO'?'ber':'bof';
      html+='<tr id="sccm-row-'+ci+'-'+hi+'">'
        +'<td style="padding:4px 10px"><input type="checkbox" class="sccmchk-'+ci+'" data-host="'+h.hostname+'" checked style="accent-color:var(--p)" onchange="window._sccmCountSel('+ci+')"></td>'
        +'<td style="padding:4px 10px;font-weight:500">'+h.hostname+'</td>'
        +'<td style="padding:4px 10px">'+(h.entorno||'').replace('Endpoint-','')+'</td>'
        +'<td style="padding:4px 10px"><span class="bd '+adC+'">'+h.estadoAD+'</span></td>'
        +'<td style="padding:4px 10px;color:'+(h.diasQualys>15?'var(--err)':'var(--ok)')+'">'+h.diasQualys+'d</td>'
        +'<td style="padding:4px 10px"><span style="font-size:.63rem;font-weight:700;color:'+rC+'">'+risk+'</span></td>'
        +'</tr>';
    });
    html+='</tbody></table></div>';
    html+='<div style="display:flex;align-items:center;gap:8px;margin-top:8px">';
    html+='<span id="sccm-sel-'+ci+'" style="font-size:.70rem;color:var(--t2)">'+col.hosts.length+' seleccionados</span>';
    html+='<div style="margin-left:auto;display:flex;gap:6px">';
    html+='<button id="sccmCopySel-'+ci+'" onclick="window._sccmCopySel('+ci+')" '
      +'style="display:inline-flex;align-items:center;gap:4px;padding:5px 12px;border-radius:12px;border:none;background:var(--p);color:#fff;font-family:var(--fd);font-size:.73rem;font-weight:500;cursor:pointer">'
      +'<span class="material-icons-round" style="font-size:13px">content_copy</span> Copiar selección</button>';
    html+='<button onclick="window._sccmExportSel('+ci+')" '
      +'style="display:inline-flex;align-items:center;gap:4px;padding:5px 12px;border-radius:12px;border:1px solid var(--p);background:transparent;color:var(--p);font-family:var(--fd);font-size:.73rem;cursor:pointer">'
      +'<span class="material-icons-round" style="font-size:13px">download</span> CSV selección</button>';
    html+='</div></div>';
    html+='</div></div></div>'; // padding, body, card
  });
  html+='</div></div>'; // cols list + container
  ct.innerHTML=html;
};

// ── Event handlers ────────────────────────────────────────────────────────────
window._sccmToggle=function(ci){
  var b=document.getElementById('sccm-body-'+ci),ic=document.getElementById('sccm-ico-'+ci);
  if(!b)return; var open=b.style.display!=='none';
  b.style.display=open?'none':'block';
  if(ic) ic.style.transform=open?'':'rotate(180deg)';
};

window._sccmUpdatePrefix=function(v){
  _sccmPrefix=v||'VUL-';
  localStorage.setItem('sccm_prefix_v1',_sccmPrefix);
};

window._sccmGetSel=function(ci){
  var r=[];
  document.querySelectorAll('.sccmchk-'+ci+':checked').forEach(function(c){r.push(c.dataset.host);});
  return r;
};

window._sccmCountSel=function(ci){
  var sel=window._sccmGetSel(ci);
  var el=document.getElementById('sccm-sel-'+ci);
  if(el) el.textContent=sel.length+' seleccionados';
  var allChk=document.getElementById('sccmAllChk-'+ci);
  var col=_sccmCollections[ci];
  if(allChk&&col) allChk.checked=sel.length===col.hosts.length;
};

window._sccmToggleAll=function(ci,checked){
  document.querySelectorAll('.sccmchk-'+ci).forEach(function(c){c.checked=checked;});
  window._sccmCountSel(ci);
};

window._sccmVulnsToggle=function(ci){
  var rows=document.querySelectorAll('.sccm-vuln-row-'+ci);
  var btn=document.getElementById('sccmVulnToggle-'+ci);
  if(!rows.length) return;
  // Check if hidden rows exist
  var anyHidden=false;
  rows.forEach(function(r,i){ if(i>=5 && r.style.display==='none') anyHidden=true; });
  rows.forEach(function(r,i){
    if(i>=5) r.style.display=anyHidden?'flex':'none';
  });
  if(btn){
    if(anyHidden){
      btn.innerHTML='<span class="material-icons-round" style="font-size:12px">expand_less</span> Colapsar';
    } else {
      btn.innerHTML='<span class="material-icons-round" style="font-size:12px">expand_more</span> Ver todas';
    }
  }
};

window._sccmFilter=function(ci,term){
  var col=_sccmCollections[ci]; if(!col)return;
  var t=term.toLowerCase();
  col.hosts.forEach(function(h,hi){
    var row=document.getElementById('sccm-row-'+ci+'-'+hi);
    if(row) row.style.display=(!t||h.hostname.toLowerCase().includes(t)||(h.entorno||'').toLowerCase().includes(t))?'':'none';
  });
};

window._sccmCopyCol=function(ci){
  var col=_sccmCollections[ci]; if(!col)return;
  var btn=document.getElementById('sccmCopyBtn-'+ci);
  _sccmCopyToClipboard(col.hosts.map(function(h){return h.hostname;}).join('\n'),btn);
};

window._sccmCopySel=function(ci){
  var sel=window._sccmGetSel(ci); if(!sel.length)return;
  var btn=document.getElementById('sccmCopySel-'+ci);
  _sccmCopyToClipboard(sel.join('\n'),btn);
};

window._sccmExportOne=function(ci){
  var col=_sccmCollections[ci]; if(!col)return;
  var colName=document.getElementById('sccmName-'+ci);
  _sccmExportCSV(colName?colName.value:_sccmPrefix+col.id, col.hosts);
};

window._sccmExportSel=function(ci){
  var col=_sccmCollections[ci]; if(!col)return;
  var sel=new Set(window._sccmGetSel(ci));
  var colName=document.getElementById('sccmName-'+ci);
  _sccmExportCSV((colName?colName.value:_sccmPrefix+col.id)+'_sel', col.hosts.filter(function(h){return sel.has(h.hostname);}));
};

window._sccmExportAll=function(){
  var rows=['Coleccion,Hostname,Entorno,Estado AD,Dias Qualys,Dias Logon,Riesgo'];
  _sccmCollections.forEach(function(col){
    var nameEl=document.getElementById('sccmName-'+_sccmCollections.indexOf(col));
    var cn=nameEl?nameEl.value:_sccmPrefix+col.id;
    col.hosts.forEach(function(h){
      rows.push([cn,h.hostname,h.entorno||'',h.estadoAD||'',h.diasQualys||0,h.diasLogon||0,_sccmRisk(h)].join(','));
    });
  });
  var blob=new Blob([rows.join('\n')],{type:'text/csv'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=_sccmPrefix+'todas_las_colecciones.csv';
  a.click();
};

window._sccmSaveOne=function(ci){
  var col=_sccmCollections[ci]; if(!col)return;
  var nameEl=document.getElementById('sccmName-'+ci);
  var name=nameEl?nameEl.value:_sccmPrefix+col.id;
  var saved=sccmLoadSaved();
  // Evitar duplicados por nombre
  var exists=saved.findIndex(function(s){return s.name===name;});
  var entry={
    name:name, hostCount:col.hosts.length, topRisk:col.topRisk,
    date:new Date().toLocaleDateString('es-ES'), status:'pendiente',
    hosts:col.hosts.map(function(h){return{hostname:h.hostname,entorno:h.entorno,estadoAD:h.estadoAD,diasQualys:h.diasQualys,diasLogon:h.diasLogon};}),
    vulns:col.vulns
  };
  if(exists>=0) saved[exists]=entry; else saved.push(entry);
  sccmSaveSaved(saved);
  var btn=document.getElementById('sccmSaveBtn-'+ci);
  if(btn){
    var orig=btn.innerHTML;
    btn.innerHTML='<span class="material-icons-round" style="font-size:13px">check</span> ¡Guardada!';
    btn.style.background='var(--ok)';
    setTimeout(function(){btn.innerHTML=orig;btn.style.background='';window.renderSCCMPanel();},1500);
  }
};

window._sccmSaveAll=function(){
  _sccmCollections.forEach(function(col,ci){ window._sccmSaveOne(ci); });
};

window._sccmSetStatus=function(si,status){
  var saved=sccmLoadSaved();
  if(saved[si]){ saved[si].status=status; sccmSaveSaved(saved); }
};

window._sccmDeleteSaved=function(si){
  var saved=sccmLoadSaved();
  saved.splice(si,1); sccmSaveSaved(saved);
  window.renderSCCMPanel();
};

window._sccmCopySaved=function(si){
  var saved=sccmLoadSaved();
  var sc=saved[si]; if(!sc||!sc.hosts)return;
  var btn=document.getElementById('sccmSavedCopy-'+si);
  _sccmCopyToClipboard(sc.hosts.map(function(h){return h.hostname;}).join('\n'),btn);
};

window._sccmExportSaved=function(si){
  var saved=sccmLoadSaved();
  var sc=saved[si]; if(!sc||!sc.hosts)return;
  _sccmExportCSV(sc.name, sc.hosts);
};
