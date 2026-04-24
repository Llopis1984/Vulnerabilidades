// CISA KEV — EPSS + CVEProject enrichment + Panel
// EPSS — Exploit Prediction Scoring System (FIRST.org)
// Fuente: github.com/jgamblin/KEV_EPSS — actualizado cada 12h via GitHub Actions
// CSV: CVE,CVSS3,EPSS,EPSS Percentile,Description,Vendor,Product
// ══════════════════════════════════════════════════════════════════════════════
var _epssData = {};        // CVE_ID → {cvss3, epss, epssPercentile, vendor, product}
var _epssLoaded = false;
var _epssLoading = false;

async function loadEPSSData(onDone){
  if(_epssLoaded){ if(onDone) onDone(); return; }
  if(_epssLoading) return;
  _epssLoading = true;

  // Si ya se precargó, reutilizar
  if(_epssLoaded){ if(onDone) onDone(); return; }
  var url = 'https://raw.githubusercontent.com/jgamblin/KEV_EPSS/main/epss_kev_nvd.csv';
  try{
    var epssRes = await _fetchCached(url, 'epss', _CACHE_TTL.epss);
    var text = epssRes.data;
    var lines = text.split('\n');
    var headers = lines[0].toLowerCase().split(',').map(function(h){return h.trim();});
    var iCVE = headers.indexOf('cve');
    var iCVSS = headers.indexOf('cvss3');
    var iEPSS = headers.indexOf('epss');
    var iPct = headers.findIndex(function(h){return h.includes('percentile');});
    var iDesc = headers.indexOf('description');
    var iVendor = headers.indexOf('vendor');
    var iProd = headers.indexOf('product');

    for(var i=1; i<lines.length; i++){
      var line = lines[i].trim();
      if(!line) continue;
      // Handle quoted fields (description may contain commas)
      var parts = _parseCSVLine(line);
      var cve = parts[iCVE]||'';
      if(!cve.startsWith('CVE-')) continue;
      _epssData[cve] = {
        cvss3: parseFloat(parts[iCVSS])||null,
        epss: parseFloat(parts[iEPSS])||null,
        epssPercentile: parseFloat(parts[iPct])||null,
        description: (parts[iDesc]||'').replace(/^"|"$/g,'').trim(),
        vendor: parts[iVendor]||'',
        product: parts[iProd]||''
      };
    }
    _epssLoaded = true;
    console.log('[EPSS] Cargados '+Object.keys(_epssData).length+' CVEs desde GitHub KEV_EPSS');
  } catch(e){
    console.warn('[EPSS] Error cargando datos:', e.message);
  }
  _epssLoading = false;
  if(onDone) onDone();
}

function _parseCSVLine(line){
  var result=[], current='', inQuotes=false;
  for(var i=0;i<line.length;i++){
    var ch=line[i];
    if(ch==='"'){ inQuotes=!inQuotes; }
    else if(ch===','&&!inQuotes){ result.push(current); current=''; }
    else current+=ch;
  }
  result.push(current);
  return result;
}

function epssColor(score){
  if(score===null||score===undefined) return 'var(--t2)';
  if(score>=0.7) return 'var(--err)';
  if(score>=0.4) return 'var(--warn)';
  if(score>=0.1) return 'var(--p)';
  return 'var(--ok)';
}

function epssBar(score){
  if(score===null||score===undefined) return '';
  var pct = Math.round(score*100);
  var col = epssColor(score);
  return '<div style="display:flex;align-items:center;gap:6px;margin-top:3px">'
    +'<div style="flex:1;height:5px;background:var(--olv);border-radius:3px;overflow:hidden">'
    +'<div style="height:100%;width:'+pct+'%;background:'+col+';border-radius:3px;transition:width .5s"></div>'
    +'</div>'
    +'<span style="font-size:.60rem;color:'+col+';font-weight:600;min-width:28px">'+pct+'%</span>'
    +'</div>';
}

// CVE Data — desde CVEProject/cvelistV5 en GitHub (raw.githubusercontent.com soporta CORS)
// Mismo mecanismo que el catálogo CISA KEV: funciona desde file:// y cualquier origen.
// URL: https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/YEAR/NNNxxx/CVE-ID.json

function nvdSeverityColor(sev){
  if(!sev) return 'var(--t2)';
  var s=sev.toUpperCase();
  if(s==='CRITICAL') return 'var(--err)';
  if(s==='HIGH') return 'var(--warn)';
  if(s==='MEDIUM') return 'var(--p)';
  return 'var(--ok)';
}

var _cveCache = {}; // CVE_ID → {published, cvssScore, severity, description, source}
var _cveLoading = false;

function _cveGitHubUrl(cveId){
  // CVE-2026-21514 → cves/2026/21xxx/CVE-2026-21514.json
  var parts = cveId.split('-');
  if(parts.length < 3) return null;
  var year = parts[1];
  var num = parseInt(parts[2], 10);
  var folder = Math.floor(num / 1000) + 'xxx';
  return 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'+year+'/'+folder+'/'+cveId+'.json';
}

function _parseCVERecord(data){
  if(!data) return null;
  var meta = data.cveMetadata || {};
  var cna = (data.containers || {}).cna || {};
  // Published date
  // datePublished puede estar en diferentes campos según versión del schema
  var published = (meta.datePublished || meta.dateReserved || '').split('T')[0] || null;
  // Si el CVE está en estado PUBLISHED pero sin fecha, intentar extraer del ID
  if(!published && meta.state === 'PUBLISHED' && meta.cveId){
    var yearMatch = meta.cveId.match(/CVE-(\d{4})-/);
    // Solo usar año como fallback si no hay otra opción (impreciso)
  }
  // CVSS — prefer v3.1 > v3.0 > v4.0 from CNA metrics, then ADP
  var cvssScore = null, severity = null;
  var allMetrics = (cna.metrics || []);
  // Also check ADP containers
  ((data.containers || {}).adp || []).forEach(function(a){ (a.metrics||[]).forEach(function(m){ allMetrics.push(m); }); });
  allMetrics.forEach(function(m){
    if(cvssScore) return;
    ['cvssV3_1','cvssV3_0','cvssV4_0','cvssV2_0'].forEach(function(k){
      if(!cvssScore && m[k]){
        cvssScore = m[k].baseScore || m[k].vectorString && parseFloat((m[k].vectorString.match(/\/SCORE:(\d+\.?\d*)/)||[])[1]) || null;
        severity = m[k].baseSeverity || m[k].severity || null;
      }
    });
  });
  // Description (English)
  var description = '';
  (cna.descriptions || []).forEach(function(d){ if(d.lang==='en' && !description) description = d.value || ''; });
  return { published: published, cvssScore: cvssScore, severity: severity, description: description, source: 'CVEProject/cvelistV5' };
}

async function enrichWithCVEProject(cveList, onProgress, onDone){
  if(!cveList || cveList.length === 0){ if(onDone) onDone(); return; }
  var pending = cveList.filter(function(c){ return !_cveCache[c]; });
  if(pending.length === 0){ if(onDone) onDone(); return; }

  _cveLoading = true;
  var done = 0, notFound = 0;
  var BATCH = 5; // F5-PERF: 5 concurrent fetches per batch

  async function fetchOne(cve){
    var url = _cveGitHubUrl(cve);
    if(!url){ _cveCache[cve] = {published:null,cvssScore:null,severity:null,description:'',notFound:true}; notFound++; return; }
    try{
      var r = await _fetchTimeout(url, 10000);
      if(r.ok){
        var data = await r.json();
        var parsed = _parseCVERecord(data);
        _cveCache[cve] = parsed || {published:null,cvssScore:null,severity:null,description:'',notFound:true};
        if(!parsed || !parsed.published) notFound++;
      } else {
        _cveCache[cve] = {published:null,cvssScore:null,severity:null,description:'',notFound:true};
        notFound++;
      }
    } catch(e){
      _cveCache[cve] = {published:null,cvssScore:null,severity:null,description:'',error:e.message};
      notFound++;
    }
    done++;
    if(onProgress) onProgress(done, pending.length, notFound);
  }

  for(var b = 0; b < pending.length; b += BATCH){
    var batch = pending.slice(b, b + BATCH);
    await Promise.all(batch.map(fetchOne));
    if(b + BATCH < pending.length) await new Promise(function(res){ setTimeout(res, 100); });
  }
  _cveLoading = false;
  if(onDone) onDone();
}

// CISA KEV — Panel completo con filtrado de equipos
// ══════════════════════════════════════════════════════════════════════════════
// Aplicar datos de _cveCache a kevVulns y calcular Zero Day
function _applyEnrichment(kevVulns){
  kevVulns.forEach(function(e){
    var v = e[1], kevInfo = v._kevInfo||{};
    var kevCveArr = [...v.kevCves];
    // Fecha publicación: CVEProject primero, fallback Qualys
    var pubDate = null;
    kevCveArr.forEach(function(c){
      var d=_cveCache[c];
      if(d&&d.published&&!pubDate) pubDate=d.published;
    });
    if(!pubDate){
      window._raw&&window._raw.forEach(function(r){ if(r.vulnName===e[0]&&r.fechaPub&&!pubDate) pubDate=r.fechaPub.split(' ')[0]; });
      v._pubSource = 'Qualys';
    } else {
      v._pubSource = 'CVEProject/cvelistV5';
    }
    v._pubDate = pubDate;
    var rawGap = (pubDate&&kevInfo.dateAdded) ? Math.round((new Date(kevInfo.dateAdded)-new Date(pubDate))/864e5) : null;
    v._gapDays = rawGap!==null ? Math.abs(rawGap) : null;
    v._isZeroDay  = v._gapDays!==null && v._gapDays===0;   // mismo día: explotado al publicarse
    v._isNDay     = v._gapDays!==null && v._gapDays>=1 && v._gapDays<=14; // N-Day crítico
    // Extraer VPR de Qualys SIEMPRE (independientemente de si CVEProject tiene datos)
    var vprStr=v.vpr||'';
    var vprNum=parseFloat((vprStr.match(/\d+\.?\d*/)||[null])[0]);
    v._qualysVPR = vprNum||null;
    v._qualysSev = vprNum>=9?'CRITICAL':vprNum>=7?'HIGH':vprNum>=4?'MEDIUM':vprNum?'LOW':null;

    // CVSS oficial: CVEProject/cvelistV5 si disponible
    var bestScore=null, bestSev=null;
    kevCveArr.forEach(function(c){ var d=_cveCache[c]; if(d&&d.cvssScore&&(bestScore===null||d.cvssScore>bestScore)){bestScore=d.cvssScore;bestSev=d.severity;} });
    if(bestScore){
      v._cvssScore=bestScore; v._cvssSev=bestSev; v._cvssSource='CVEProject/cvelistV5';
    } else {
      v._cvssScore=vprNum||null;
      v._cvssSev=v._qualysSev;
      v._cvssSource='Qualys VPR';
    }

    // Detectar escalada de riesgo: VPR Qualys vs CVSS CVEProject
    v._scoreEscalated = false;
    v._scoreDropped = false;
    if(v._qualysVPR && bestScore && v._cvssSource==='CVEProject/cvelistV5'){
      var diff = bestScore - v._qualysVPR;
      if(diff >= 2) v._scoreEscalated = true;   // subió ≥2 puntos → alerta
      if(diff <= -2) v._scoreDropped = true;     // bajó ≥2 puntos → info
    }
    // Descripción — CVEProject primero, fallback EPSS CSV
    v._description='';
    kevCveArr.forEach(function(c){ var d=_cveCache[c]; if(d&&d.description&&!v._description) v._description=d.description; });
    if(!v._description){
      kevCveArr.forEach(function(c){ var d=_epssData[c]; if(d&&d.description&&!v._description) v._description=d.description; });
    }

    // EPSS score — del CSV de GitHub (ya tiene todos los KEV CVEs)
    v._epss=null; v._epssPercentile=null; v._epssVendor=''; v._epssProduct='';
    kevCveArr.forEach(function(c){
      var d=_epssData[c];
      if(d&&d.epss!==null&&v._epss===null){
        v._epss=d.epss;
        v._epssPercentile=d.epssPercentile;
        if(d.vendor) v._epssVendor=d.vendor;
        if(d.product) v._epssProduct=d.product;
      }
    });
  });
  // Zero Day CRÍTICO = gap=0 Y EPSS>=30% (los realmente peligrosos)
  window._kevZdCount     = kevVulns.filter(function(e){ return e[1]._isZeroDay && e[1]._epss!==null && e[1]._epss>=0.3; }).length;
  window._kevNDayCount   = kevVulns.filter(function(e){ return e[1]._isNDay    && e[1]._epss!==null && e[1]._epss>=0.3; }).length;
  window._kevZdAllCount  = kevVulns.filter(function(e){ return e[1]._isZeroDay; }).length; // total gap=0 (informativo)
}

window.renderKEVPanel = function(){
  var ct = document.getElementById('ct-kev'); if(!ct) return;
  var raw = window._raw;
  if(!raw||raw.length===0){ ct.innerHTML='<div style="text-align:center;padding:60px;color:var(--t2)"><span class="material-icons-round" style="font-size:48px;display:block;opacity:.3;margin-bottom:12px">shield</span>Carga un CSV primero</div>'; return; }
  if(!window._kevSet||window._kevSet.size===0){
    ct.innerHTML='<div style="text-align:center;padding:60px;color:var(--t2)"><span class="material-icons-round" style="font-size:48px;display:block;opacity:.3;margin-bottom:12px">shield</span>'
      +(window._kevStatus&&window._kevStatus.ok
        ?'<p>Parque limpio — ninguna vulnerabilidad en el catálogo CISA KEV.</p>'
        :'<p>Catálogo CISA KEV no disponible todavía.<br>Si no se descarga automáticamente, sube el JSON manualmente desde la pantalla de inicio.</p>')
      +'</div>';
    return;
  }

  var kevVulns = window._kevVulns || [];
  var zdCount = window._kevZdCount || 0;
  var st = window._kevStatus || {};

  // Cargar EPSS si no está disponible aún
  if(!_epssLoaded && !_epssLoading){
    loadEPSSData(function(){ window.renderKEVPanel(); });
    return;
  }
  if(_epssLoading){
    ct.innerHTML='<div style="max-width:1440px;margin:0 auto;padding:40px 20px;text-align:center"><div style="display:inline-flex;align-items:center;gap:12px;background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:16px 24px"><div class="spinner" style="width:20px;height:20px;border-width:3px"></div><div style="font-family:var(--fd);font-size:.85rem;font-weight:500">Cargando datos EPSS desde GitHub…</div></div></div>';
    return;
  }

  // Recopilar CVEs únicos para enriquecer desde CVEProject/cvelistV5 (GitHub raw - CORS OK)
  var allKevCves = [];
  kevVulns.forEach(function(e){ [...e[1].kevCves].forEach(function(c){ if(allKevCves.indexOf(c)<0) allKevCves.push(c); }); });
  var needEnrich = allKevCves.filter(function(c){ return !_cveCache[c]; });

  if(needEnrich.length > 0 && !_cveLoading){
    var progressHtml = '<div style="max-width:1440px;margin:0 auto;padding:40px 20px;text-align:center">'
      +'<div style="display:inline-flex;align-items:center;gap:12px;background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:16px 24px">'
      +'<div class="spinner" style="width:20px;height:20px;border-width:3px"></div>'
      +'<div style="text-align:left">'
      +'<div style="font-family:var(--fd);font-size:.85rem;font-weight:500">Consultando CVEProject/cvelistV5 (GitHub)…</div>'
      +'<div style="font-size:.72rem;color:var(--t2)" id="cveProgressSub">0 / '+needEnrich.length+' CVEs · ~'+Math.ceil(needEnrich.length*0.15)+'s</div>'
      +'</div></div></div>';
    ct.innerHTML = progressHtml;
    enrichWithCVEProject(allKevCves,
      function(done,total,notFound){
        var sub=document.getElementById('cveProgressSub');
        if(sub) sub.textContent=done+' / '+total+' CVEs'+(notFound>0?' · '+notFound+' sin datos en GitHub':'');
      },
      function(){ _applyEnrichment(kevVulns); window.renderKEVPanel(); }
    );
    return;
  }

  // Ya enriquecidos — aplicar y renderizar
  _applyEnrichment(kevVulns);


  // Helper: compute days between two date strings
  function daysBetween(d1,d2){if(!d1||!d2)return null;try{return Math.abs(Math.round((new Date(d1)-new Date(d2))/864e5));}catch(e){return null;}}

  var html='<div class="kev-panel">';

  // ── Header ──────────────────────────────────────────────────────────────────
  html+='<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px">'
    +'<div>'
    +'<div style="font-family:var(--fd);font-size:1.05rem;font-weight:600;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="color:#7c3aed">shield</span> CISA KEV — Vulnerabilidades Explotadas Activamente</div>'
    +'<div style="font-size:.73rem;color:var(--t2);margin-top:3px">Catálogo CISA v'+(st.catalogVersion||'?')+' · '+st.checked+' entradas comprobadas · Clic en una vulnerabilidad para ver y filtrar equipos afectados</div>'
    +'</div>'
    +(function(){
        var c=_cacheGet('kev');
        if(!c) return '';
        var mins=Math.round((Date.now()-c.timestamp)/60000);
        var label=mins<60?mins+'min':(Math.round(mins/60))+'h';
        var fresh=mins<60*6;
        return '<div style="font-size:.65rem;color:'+(fresh?'var(--ok)':'var(--warn)')+';margin-top:2px">'
          +(fresh?'✓ Caché actualizada':'⏱ Caché ')+label+' antiguo'
          +(c.meta&&c.meta.changed===false?' · sin cambios desde descarga anterior':'')
          +'</div>';
      })()
    +'</div></div>';

  // ── Summary KPIs ─────────────────────────────────────────────────────────
  var ransomCount=kevVulns.filter(function(e){return e[1]._kevInfo&&e[1]._kevInfo.ransomware==='Known';}).length;
  var hostCount=window._kevHostSet?window._kevHostSet.size:0;


  html+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px">';
  html+='<div class="kc" style="border-left-color:#7c3aed"><div class="kl">Vulnerabilidades KEV</div><div class="kv" style="color:#7c3aed">'+kevVulns.length+'</div><div class="ks">en este parque</div></div>';
  html+='<div class="kc er"><div class="kl">Equipos afectados</div><div class="kv">'+hostCount+'</div><div class="ks">con vulns KEV</div></div>';
  html+='<div class="kc er"><div class="kl">⚡ Zero Day críticos</div><div class="kv" style="color:var(--err)">'+zdCount+'</div><div class="ks">gap=0 + EPSS≥30%</div></div>';
  html+='<div class="kc wa"><div class="kl">🔒 Ransomware</div><div class="kv" style="color:var(--warn)">'+ransomCount+'</div><div class="ks">usadas en campañas</div></div>';
  html+='</div>';

  // ── Filtros + Búsqueda ──────────────────────────────────────────────────────
  var activeFilter = ct._kevFilter || 'todos';
  var activeSort   = ct._kevSort   || 'criticidad';
  var searchTerm   = ct._kevSearch || '';

  // Calcular nivel de amenaza para cada vuln (necesario para filtrar y ordenar)
  function _kevThreatOrder(v){
    var isRealZD  = v._isZeroDay && v._epss!==null && v._epss>=0.3;
    var isRealND  = v._isNDay    && v._epss!==null && v._epss>=0.3;
    var isAltoEPS = v._epss!==null && v._epss>=0.3;
    var isAltoZD  = v._isZeroDay || v._isNDay;
    if(isRealZD)           return {order:0, label:'ZERO DAY CRÍTICO'};
    if(isRealND)           return {order:1, label:'N-DAY CRÍTICO'};
    if(isAltoEPS||isAltoZD)return {order:2, label:'ALTO'};
    return                        {order:3, label:'MEDIO'};
  }
  kevVulns.forEach(function(e){ e[1]._threatInfo = _kevThreatOrder(e[1]); });

  // Filtrar
  var filtered = kevVulns.filter(function(e){
    var v=e[1], name=e[0];
    if(searchTerm && !name.toLowerCase().includes(searchTerm) &&
       !(v._kevInfo&&v._kevInfo.vendor&&v._kevInfo.vendor.toLowerCase().includes(searchTerm)))
      return false;
    if(activeFilter==='todos') return true;
    if(activeFilter==='zerodaycritico') return v._threatInfo.order===0;
    if(activeFilter==='ndaycritico')    return v._threatInfo.order===1;
    if(activeFilter==='alto')           return v._threatInfo.order===2;
    if(activeFilter==='medio')          return v._threatInfo.order===3;
    if(activeFilter==='ransomware')     return v._kevInfo&&v._kevInfo.ransomware==='Known';
    return true;
  });

  // Ordenar
  filtered.sort(function(a,b){
    if(activeSort==='criticidad'){
      var d = a[1]._threatInfo.order - b[1]._threatInfo.order;
      return d!==0 ? d : b[1].hosts.size - a[1].hosts.size;
    }
    if(activeSort==='equipos') return b[1].hosts.size - a[1].hosts.size;
    if(activeSort==='epss'){
      var ea=a[1]._epss||0, eb=b[1]._epss||0;
      return eb-ea;
    }
    if(activeSort==='fecha') return (a[1]._kevInfo&&b[1]._kevInfo) ?
      (a[1]._kevInfo.dateAdded||'').localeCompare(b[1]._kevInfo.dateAdded||'') : 0;
    return 0;
  });

  // Counts por nivel para los chips de filtro
  var cntZD  = kevVulns.filter(function(e){return e[1]._threatInfo.order===0;}).length;
  var cntND  = kevVulns.filter(function(e){return e[1]._threatInfo.order===1;}).length;
  var cntAlt = kevVulns.filter(function(e){return e[1]._threatInfo.order===2;}).length;
  var cntMed = kevVulns.filter(function(e){return e[1]._threatInfo.order===3;}).length;
  var cntRan = kevVulns.filter(function(e){return e[1]._kevInfo&&e[1]._kevInfo.ransomware==='Known';}).length;

  function kevFC(val,label,count,color){
    var isActive = activeFilter===val;
    var bg = isActive?(color?'rgba(217,48,37,.1)':'var(--pc)'):'var(--s1)';
    var bc = isActive?(color||'var(--p)'):'var(--ol)';
    var tc = isActive?(color||'var(--p)'):'var(--t2)';
    return '<button data-kevf="'+val+'" '
      +'style="display:inline-flex;align-items:center;gap:4px;padding:5px 12px;border-radius:16px;border:1.5px solid '+bc+';background:'+bg+';color:'+tc+';font-family:var(--fd);font-size:.72rem;font-weight:'+(isActive?'600':'400')+';cursor:pointer;white-space:nowrap">'
      +label+(count!==undefined?' <span style="opacity:.7;font-size:.65rem">('+count+')</span>':'')
      +'</button>';
  }

  html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:14px 18px;margin-bottom:12px">';
  // Búsqueda
  html+='<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">';
  html+='<div style="display:flex;align-items:center;gap:6px;background:var(--s2);border:1px solid var(--ol);border-radius:20px;padding:5px 12px;flex:1;min-width:180px;max-width:340px">'
    +'<span class="material-icons-round" style="font-size:16px;color:var(--t2)">search</span>'
    +'<input type="text" id="kevSearch" placeholder="Buscar vulnerabilidad o vendor..." value="'+searchTerm+'" '
    +'oninput="window._kevSetSearch(this.value)" '
    +'style="border:none;outline:none;background:none;font-size:.78rem;width:100%;color:var(--t)">'
    +'</div>';
  // Ordenar por
  html+='<div style="display:flex;align-items:center;gap:6px;flex-shrink:0">'
    +'<span style="font-size:.70rem;color:var(--t2)">Ordenar:</span>'
    +'<select onchange="window._kevSetSort(this.value)" style="font-size:.75rem;padding:5px 8px;border:1px solid var(--ol);border-radius:8px;font-family:var(--fb);cursor:pointer;background:var(--s1)">'
    +['criticidad','equipos','epss','fecha'].map(function(s){
        var labels={criticidad:'Criticidad',equipos:'Nº equipos',epss:'EPSS',fecha:'Fecha KEV'};
        return '<option value="'+s+'"'+(activeSort===s?' selected':'')+'>'+labels[s]+'</option>';
      }).join('')
    +'</select>';
  html+='<span style="font-size:.70rem;color:var(--t2);margin-left:4px">'+filtered.length+' de '+kevVulns.length+'</span>';
  html+='</div></div>';
  // Chips de filtro por nivel
  html+='<div style="display:flex;gap:6px;flex-wrap:wrap">';
  html+=kevFC('todos','Todos');
  html+=kevFC('zerodaycritico','⚡ Zero Day crítico',cntZD,'var(--err)');
  html+=kevFC('ndaycritico','🔴 N-Day crítico',cntND,'var(--err)');
  html+=kevFC('alto','📈 Alto',cntAlt,'var(--warn)');
  html+=kevFC('medio','🔒 Medio',cntMed,'var(--p)');
  if(cntRan>0) html+=kevFC('ransomware','🔒 Ransomware',cntRan,'#7c3aed');
  html+='</div></div>';

  // ── Vuln list ─────────────────────────────────────────────────────────────
  if(filtered.length===0){
    html+='<div style="text-align:center;padding:40px;color:var(--t2);background:var(--s1);border-radius:var(--r);box-shadow:var(--e1)">'
      +'<span class="material-icons-round" style="font-size:40px;opacity:.3;display:block;margin-bottom:8px">filter_list_off</span>'
      +'Sin resultados para este filtro.</div>';
  }

  filtered.forEach(function(e,gi){
    var name=e[0], v=e[1];
    var kevInfo=v._kevInfo||{};
    var isRansom=kevInfo.ransomware==='Known';
    var kevCveArr=[...v.kevCves];
    var epssHighlight = v._epss!==null && v._epss>=0.7;
    var borderCol = v._isZeroDay?'var(--err)':v._isNDay?'var(--warn)':'#7c3aed';

    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);margin-bottom:8px;overflow:hidden;border-left:3px solid '+borderCol+'">';

    // Nivel de amenaza unificado
    // Zero Day SOLO si: gap=0 días (mismo día del parche) Y EPSS>=30% (amenaza activa)
    // Criterio: necesitas ambas condiciones para que sea realmente crítico
    var threatLevel, threatColor, threatBg, threatIcon, threatExplain;
    var epssNum = v._epss!==null ? Math.round(v._epss*100) : null;
    var isRealZeroDay = v._isZeroDay && v._epss!==null && v._epss>=0.3;
    var isRealNDay    = v._isNDay    && v._epss!==null && v._epss>=0.3;

    if(isRealZeroDay){
      threatLevel='ZERO DAY CRÍTICO'; threatColor='var(--err)'; threatBg='rgba(217,48,37,.09)';
      threatIcon='⚡'; threatExplain='Explotado mismo día del parche + EPSS '+epssNum+'% — amenaza activa en curso';
    } else if(isRealNDay){
      threatLevel='N-DAY CRÍTICO'; threatColor='var(--err)'; threatBg='rgba(217,48,37,.09)';
      threatIcon='🔴'; threatExplain='Explotado '+v._gapDays+'d tras el parche + EPSS '+epssNum+'% — amenaza activa en curso';
    } else if(v._epss!==null && v._epss>=0.3){
      threatLevel='ALTO'; threatColor='var(--warn)'; threatBg='rgba(249,171,0,.07)';
      threatIcon='📈'; threatExplain='EPSS '+epssNum+'% — alta probabilidad de explotación activa próximos 30 días';
    } else if(v._isZeroDay){
      threatLevel='ALTO'; threatColor='var(--warn)'; threatBg='rgba(249,171,0,.07)';
      threatIcon='🔒'; threatExplain='Explotado en Patch Tuesday (gap=0) · EPSS '+(epssNum!==null?epssNum+'%':'—')+' — riesgo de nuevos ataques bajo';
    } else if(v._isNDay){
      threatLevel='ALTO'; threatColor='var(--warn)'; threatBg='rgba(249,171,0,.07)';
      threatIcon='🔒'; threatExplain='Explotado '+v._gapDays+'d tras publicación · EPSS '+(epssNum!==null?epssNum+'%':'—')+' — riesgo de nuevos ataques bajo';
    } else {
      threatLevel='MEDIO'; threatColor='var(--p)'; threatBg='rgba(26,115,232,.04)';
      threatIcon='🔒'; threatExplain='Confirmado explotado por CISA · parchear para eliminar riesgo';
    }
    if(isRansom){ threatLevel='⚠ '+threatLevel+' + RANSOMWARE'; threatColor='var(--err)'; threatBg='rgba(217,48,37,.09)'; }

    // Card header — always visible
    html+='<div style="display:flex;align-items:flex-start;gap:10px;padding:12px 16px;cursor:pointer;user-select:none;'+( v._isZeroDay||v._isNDay?'background:'+threatBg:'')+'" onclick="window._kevPanelToggle('+gi+')">'
      +'<span class="material-icons-round" style="font-size:16px;color:var(--t2);transition:transform .2s;flex-shrink:0;margin-top:3px" id="kevp-ico-'+gi+'">expand_more</span>'
      +'<div style="flex:1;min-width:0">'
      // Fila 1: nombre
      +'<div style="font-weight:600;font-size:.83rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:4px">'+name+'</div>'
      // Fila 2: nivel de amenaza unificado — la clave
      +'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:3px">'
      +'<span style="display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:6px;font-size:.68rem;font-weight:700;color:'+threatColor+';background:'+threatBg+';border:1px solid '+threatColor+'40">'+threatIcon+' '+threatLevel+'</span>'
      +'<span style="font-size:.72rem;color:var(--t2)">'+threatExplain+'</span>'
      +'</div>'
      // Fila 3: metadatos secundarios
      +'<div style="display:flex;gap:10px;flex-wrap:wrap;font-size:.67rem;color:var(--t2)">'
      +'<span style="font-weight:600;color:var(--err)">'+v.hosts.size+' equipo'+(v.hosts.size>1?'s afectados':' afectado')+'</span>'
      +((v._epssVendor||kevInfo.vendor)?'<span>'+(v._epssVendor||kevInfo.vendor)+((v._epssProduct||kevInfo.product)?' · '+(v._epssProduct||kevInfo.product):'')+'</span>':'')
      +(kevInfo.dateAdded?'<span>KEV '+kevInfo.dateAdded+'</span>':'')
      +(isRansom?'<span style="color:#7c3aed;font-weight:600">🔒 Usado en ransomware</span>':'')
      +'</div>'
      +'</div>'
      +'</div>';


    // Expanded detail
    html+='<div id="kevp-detail-'+gi+'" style="display:none;border-top:1px solid var(--olv)">';

    // Metadata grid — fuente dinámica: CVEProject/cvelistV5 si disponible, Qualys como fallback
    var cvssColor=nvdSeverityColor(v._cvssSev);
    var pubSrc = v._pubSource||'Qualys';
    var pubIsGitHub = pubSrc==='CVEProject/cvelistV5';
    var cvssIsGitHub = v._cvssSource==='CVEProject/cvelistV5';
    html+='<div style="padding:12px 16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px">';
    // Fecha publicación — label y color según fuente
    html+='<div style="background:var(--s2);border-radius:8px;padding:8px 12px;'+(pubIsGitHub?'border:1px solid rgba(26,115,232,.2)':'')+'">'
      +'<div style="font-size:.60rem;text-transform:uppercase;letter-spacing:.3px;color:var(--t2);font-weight:500;margin-bottom:3px">Publicación CVE</div>'
      +'<div style="font-family:var(--fd);font-weight:700;font-size:.88rem">'+(v._pubDate||'—')+'</div>'
      +'<div style="font-size:.65rem;color:'+(pubIsGitHub?'var(--p)':'var(--t2)')+'">'+pubSrc+'</div></div>';
    // CISA KEV
    html+='<div style="background:var(--s2);border-radius:8px;padding:8px 12px">'
      +'<div style="font-size:.60rem;text-transform:uppercase;letter-spacing:.3px;color:var(--t2);font-weight:500;margin-bottom:3px">Añadido a CISA KEV</div>'
      +'<div style="font-family:var(--fd);font-weight:700;font-size:.88rem">'+(kevInfo.dateAdded||'—')+'</div>'
      +'<div style="font-size:.65rem;color:var(--t2)">Explotación activa confirmada</div></div>';
    // Timing card — cuándo se explotó respecto al parche
    if(v._gapDays!==null&&v._gapDays!==undefined){
      var gapColor = v._isZeroDay?'var(--err)':v._isNDay?'var(--warn)':'var(--ok)';
      var gapLabel, gapSub;
      if(v._isZeroDay){
        gapLabel='⚡ Mismo día del parche';
        gapSub='Microsoft publicó parche y CISA confirmó explotación el mismo día. Defensores no tuvieron margen.';
      } else if(v._isNDay){
        gapLabel='🔴 '+v._gapDays+' días tras el parche';
        gapSub='N-Day crítico: explotado muy poco después de publicarse. Ventana de parcheo muy corta.';
      } else {
        gapLabel=v._gapDays+'d tras el parche';
        gapSub='Tiempo disponible para parchear antes de explotación activa confirmada.';
      }
      html+='<div style="background:var(--s2);border-radius:8px;padding:8px 12px;'+(v._isZeroDay||v._isNDay?'border:1px solid '+gapColor+'40':'')+'">'
        +'<div style="font-size:.60rem;text-transform:uppercase;letter-spacing:.3px;color:var(--t2);font-weight:500;margin-bottom:3px">¿Cuándo se explotó?</div>'
        +'<div style="font-family:var(--fd);font-weight:700;font-size:.85rem;color:'+gapColor+'">'+gapLabel+'</div>'
        +'<div style="font-size:.62rem;color:var(--t2);line-height:1.4;margin-top:3px">'+gapSub+'</div>'
        +'<div style="font-size:.58rem;color:var(--t2);margin-top:3px;opacity:.7">Fuente fecha: '+pubSrc+'</div></div>';
    }
    // CVSS card — muestra ambos scores (CVEProject + Qualys VPR) para detectar escaladas
    if(v._cvssScore || v._qualysVPR){
      var hasTwo = cvssIsGitHub && v._qualysVPR;
      var escalBg = v._scoreEscalated?'background:rgba(217,48,37,.06);border:1px solid rgba(217,48,37,.3)':
                    v._scoreDropped?'background:rgba(24,128,56,.06);border:1px solid rgba(24,128,56,.2)':
                    (cvssIsGitHub?'border:1px solid rgba(26,115,232,.2)':'');
      html+='<div style="background:var(--s2);border-radius:8px;padding:8px 12px;'+escalBg+'">'
        +'<div style="font-size:.60rem;text-transform:uppercase;letter-spacing:.3px;color:var(--t2);font-weight:500;margin-bottom:5px">'
        +(v._scoreEscalated?'⚠ Score escalado':'')
        +(v._scoreDropped?'↘ Score reducido':'')
        +(!v._scoreEscalated&&!v._scoreDropped?'Puntuación':'')
        +'</div>';

      // Score principal (CVEProject si disponible)
      if(v._cvssScore){
        html+='<div style="display:flex;align-items:baseline;gap:6px;margin-bottom:3px">'
          +'<span style="font-size:.60rem;font-weight:600;color:var(--t2);min-width:52px">CVEProject</span>'
          +'<span style="font-family:var(--fd);font-weight:700;font-size:.95rem;color:'+cvssColor+'">'+v._cvssScore+'</span>'
          +'<span style="font-size:.68rem;font-weight:500;color:'+cvssColor+'">'+( v._cvssSev||'')+'</span>'
          +(cvssIsGitHub?'':'<span style="font-size:.58rem;color:var(--t2)">(Qualys)</span>')
          +'</div>';
      }

      // Qualys VPR si hay también CVEProject (para comparar)
      if(hasTwo){
        var qColor = nvdSeverityColor(v._qualysSev);
        var arrow = v._scoreEscalated ? ' <span style="color:var(--err)">↑</span>' : v._scoreDropped ? ' <span style="color:var(--ok)">↓</span>' : '';
        html+='<div style="display:flex;align-items:baseline;gap:6px;'+(v._scoreEscalated||v._scoreDropped?'padding-top:3px;border-top:1px dashed var(--olv)':'')+'">'
          +'<span style="font-size:.60rem;font-weight:600;color:var(--t2);min-width:52px">Qualys VPR</span>'
          +'<span style="font-family:var(--fd);font-weight:700;font-size:.88rem;color:'+qColor+'">'+v._qualysVPR+'</span>'
          +'<span style="font-size:.68rem;color:'+qColor+'">'+( v._qualysSev||'')+arrow+'</span>'
          +'</div>';
      }

      html+='<div style="font-size:.60rem;color:var(--p);margin-top:4px"><a href="https://nvd.nist.gov/vuln/detail/'+(kevCveArr[0]||'')+'" target="_blank" style="color:var(--p)">Ver en NVD ↗</a></div>'
        +'</div>';
    }
    // EPSS card
    if(v._epss!==null){
      var epssCol=epssColor(v._epss);
      var epssNum2=Math.round(v._epss*100);
      var epssSub = epssNum2>=70 ? 'Alta probabilidad de nuevos ataques — prioridad máxima'
                  : epssNum2>=30 ? 'Probabilidad media — parchear pronto'
                  : 'Baja probabilidad de ataques nuevos (ya es conocido y se está parcheando)';
      var pctLabel=v._epssPercentile?'Top '+(100-Math.round(v._epssPercentile*100))+'% de todos los CVEs':'';
      html+='<div style="background:var(--s2);border-radius:8px;padding:8px 12px">'
        +'<div style="font-size:.60rem;text-transform:uppercase;letter-spacing:.3px;color:var(--t2);font-weight:500;margin-bottom:3px">EPSS · Riesgo explotación nueva</div>'
        +'<div style="font-family:var(--fd);font-weight:700;font-size:.88rem;color:'+epssCol+'">'+epssNum2+'%</div>'
        +epssBar(v._epss)
        +'<div style="font-size:.62rem;color:var(--t2);line-height:1.4;margin-top:3px">'+epssSub+'</div>'
        +(pctLabel?'<div style="font-size:.58rem;color:var(--t2);margin-top:2px;opacity:.7">'+pctLabel+' · Fuente: FIRST.org / jgamblin/KEV_EPSS</div>':'')
        +'</div>';
    }
    html+='</div>';


    // Descripción de CVEProject
    if(v._description){
      html+='<div style="padding:0 16px 10px">'
        +'<div style="padding:8px 12px;background:var(--s2);border-radius:8px;font-size:.75rem;line-height:1.6">'
        +'<strong style="font-size:.68rem;text-transform:uppercase;letter-spacing:.3px;color:var(--t2)">Descripción (CVEProject)</strong><br>'
        +v._description.substring(0,350)+(v._description.length>350?'…':'')
        +'</div></div>';
    }
    // CVEs + CISA action
    html+='<div style="padding:0 16px 12px;display:flex;flex-direction:column;gap:8px">';
    if(kevCveArr.length){
      html+='<div style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">'
        +'<span style="font-size:.68rem;font-weight:500;color:var(--t2);margin-right:2px">CVEs:</span>';
      kevCveArr.forEach(function(c){
        html+='<a href="https://nvd.nist.gov/vuln/detail/'+c+'" target="_blank" style="text-decoration:none">'
          +'<span class="ki-cve" style="cursor:pointer;background:rgba(124,58,237,.12);color:#7c3aed;border:1px solid rgba(124,58,237,.3)">'+c+' ↗</span></a>';
      });
      html+='</div>';
    }
    if(kevInfo.action){
      html+='<div style="padding:8px 12px;background:var(--s2);border-radius:8px;border-left:3px solid var(--warn);font-size:.75rem;line-height:1.5">'
        +'<strong style="color:var(--warn)">Acción requerida CISA:</strong> '+kevInfo.action+'</div>';
    }
    if(kevInfo.dueDate){
      html+='<div style="font-size:.70rem;color:var(--t2)">Fecha límite CISA: <strong>'+kevInfo.dueDate+'</strong></div>';
    }
    html+='</div>';


    // ── Equipos afectados ─────────────────────────────────────────────────────
    var affectedRaw = raw.filter(function(r){
      var cveList=(r.cves||'').split('|').map(function(c){return c.trim();}).filter(Boolean);
      return cveList.some(function(c){return window._kevSet.has(c)&&v.kevCves.has(c);});
    });
    // Unique hosts with details
    var hostMap={};
    affectedRaw.forEach(function(r){
      if(!hostMap[r.hostname]) hostMap[r.hostname]={hostname:r.hostname,entorno:r.entorno,estadoAD:r.estadoAD,diasQualys:r.diasQualys,diasLogon:r.diasLogon};
    });
    var affectedHosts=Object.values(hostMap).sort(function(a,b){return b.diasQualys-a.diasQualys;});

    html+='<div style="border-top:1px solid var(--olv);padding:12px 16px">';
    html+='<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap;gap:8px">'
      +'<div style="font-family:var(--fd);font-size:.80rem;font-weight:500;display:flex;align-items:center;gap:6px">'
      +'<span class="material-icons-round" style="color:var(--err);font-size:16px">devices</span>'
      +''+affectedHosts.length+' equipos con esta vulnerabilidad KEV</div>'
      +'<div style="display:flex;gap:6px">'
      +'<button class="rfbtn" onclick="window._kevExportHosts('+gi+')" style="font-size:.68rem;padding:4px 10px"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">download</span> CSV</button>'
      +'<button class="rfbtn" data-vuln="'+encodeURIComponent(name)+'" onclick="window._kevFilterDash(decodeURIComponent(this.dataset.vuln))" style="font-size:.68rem;padding:4px 10px;color:#7c3aed;border-color:#7c3aed"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">filter_list</span> Ver en Dashboard</button>'
      +'<button class="rfbtn" onclick="var t=document.querySelector(\'[data-view=sccm]\');if(t)t.click();" style="font-size:.68rem;padding:4px 10px"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">dynamic_feed</span> SCCM</button>'
      +'</div></div>';

    // Hosts table
    html+='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.73rem">'
      +'<thead><tr style="background:var(--s2)">'
      +'<th style="text-align:left;padding:6px 10px;font-family:var(--fd);font-weight:500;color:var(--t2);border-bottom:1px solid var(--olv)">Hostname</th>'
      +'<th style="text-align:left;padding:6px 10px;font-family:var(--fd);font-weight:500;color:var(--t2);border-bottom:1px solid var(--olv)">Entorno</th>'
      +'<th style="text-align:left;padding:6px 10px;font-family:var(--fd);font-weight:500;color:var(--t2);border-bottom:1px solid var(--olv)">Estado AD</th>'
      +'<th style="text-align:left;padding:6px 10px;font-family:var(--fd);font-weight:500;color:var(--t2);border-bottom:1px solid var(--olv)">Días Q</th>'
      +'<th style="text-align:left;padding:6px 10px;font-family:var(--fd);font-weight:500;color:var(--t2);border-bottom:1px solid var(--olv)">Días AD</th>'
      +'<th style="text-align:left;padding:6px 10px;font-family:var(--fd);font-weight:500;color:var(--t2);border-bottom:1px solid var(--olv)">Detalle</th>'
      +'</tr></thead><tbody>';
    affectedHosts.slice(0,50).forEach(function(h){
      var eb=h.estadoAD==='HABILITADO'?'bok':h.estadoAD==='DESHABILITADO'?'ber':'bof';
      var qb=h.diasQualys>15?'ber':h.diasQualys>7?'bwa':'bok';
      var ab=h.diasLogon>15?'ber':h.diasLogon>7?'bwa':'bok';
      html+='<tr style="border-bottom:1px solid var(--olv)" onmouseover="this.style.background=&quot;var(--s2)&quot;" onmouseout="this.style.background=&quot;&quot;">'
        +'<td style="padding:6px 10px;font-weight:500">'+h.hostname+'</td>'
        +'<td style="padding:6px 10px">'+h.entorno+'</td>'
        +'<td style="padding:6px 10px"><span class="bd '+eb+'">'+h.estadoAD+'</span></td>'
        +'<td style="padding:6px 10px"><span class="bd '+qb+'">'+h.diasQualys+'d</span></td>'
        +'<td style="padding:6px 10px"><span class="bd '+ab+'">'+h.diasLogon+'d</span></td>'
        +'<td style="padding:6px 10px"><button class="rfbtn" style="font-size:.65rem;padding:2px 8px" data-host="'+h.hostname+'" onclick="openHostModal(this.dataset.host)">Ver</button></td>'
        +'</tr>';
    });
    if(affectedHosts.length>50) html+='<tr><td colspan="6" style="padding:8px 10px;text-align:center;color:var(--t2);font-size:.70rem">... y '+(affectedHosts.length-50)+' más — exporta el CSV para el listado completo</td></tr>';
    html+='</tbody></table></div></div>';
    html+='<div style="display:flex;gap:6px;flex-wrap:wrap;padding:10px 16px;border-top:1px solid var(--olv)">'
      +'<button class="rfbtn" style="font-size:.68rem;padding:4px 10px" onclick="var t=document.querySelector(\'[data-view=sccm]\');if(t)t.click()"><span class="material-icons-round" style="font-size:12px;vertical-align:-2px">dynamic_feed</span> SCCM</button>'
      +'</div>';
    html+='</div></div>'; // close detail + card
  });

  html+='</div>';
  ct.innerHTML=html;

  // Store affected hosts per vuln for CSV export
  window._kevAffectedHosts = {};
  kevVulns.forEach(function(e){
    var name=e[0],v=e[1];
    var affectedRaw=raw.filter(function(r){
      var cveList=(r.cves||'').split('|').map(function(c){return c.trim();}).filter(Boolean);
      return cveList.some(function(c){return window._kevSet.has(c)&&v.kevCves.has(c);});
    });
    var hm={};
    affectedRaw.forEach(function(r){if(!hm[r.hostname])hm[r.hostname]={hostname:r.hostname,entorno:r.entorno,estadoAD:r.estadoAD,diasQualys:r.diasQualys,diasLogon:r.diasLogon};});
    window._kevAffectedHosts[name]=Object.values(hm);
  });
};

// KEV filter chips — delegated click (avoids quote-in-onclick issues)
document.addEventListener('click', function(e){
  var btn = e.target.closest('[data-kevf]');
  if(btn){ window._kevSetFilter(btn.dataset.kevf); }
});

// KEV filter/sort/search handlers — persist state on ct element
window._kevSetFilter=function(val){
  var ct=document.getElementById('ct-kev');
  if(ct){ct._kevFilter=val; window.renderKEVPanel();}
};
window._kevSetSort=function(val){
  var ct=document.getElementById('ct-kev');
  if(ct){ct._kevSort=val; window.renderKEVPanel();}
};
window._kevSetSearch=function(val){
  var ct=document.getElementById('ct-kev');
  if(ct){ct._kevSearch=val.toLowerCase().trim(); window.renderKEVPanel();}
};

window._kevPanelToggle=function(idx){
  var d=document.getElementById('kevp-detail-'+idx);
  var i=document.getElementById('kevp-ico-'+idx);
  if(!d)return;
  var open=d.style.display==='none';
  d.style.display=open?'block':'none';
  if(i)i.style.transform=open?'rotate(180deg)':'';
};

window._nvdKeySave=function(){
  var input=document.getElementById('nvdApiKeyInput');
  if(!input) return;
  var key=input.value.trim();
  setNVDKey(key);
  // Clear cache to force re-fetch with new key
  // (NVD cache removed)
  window.renderKEVPanel();
};

window._kevExportHosts=function(idx){
  if(!window._kevVulns||!window._kevVulns[idx])return;
  var name=window._kevVulns[idx][0];
  var hosts=window._kevAffectedHosts[name]||[];
  var csv='Hostname;Entorno;Estado AD;Dias Qualys;Dias Logon;Vulnerabilidad KEV\n';
  hosts.forEach(function(h){csv+=h.hostname+';'+h.entorno+';'+h.estadoAD+';'+h.diasQualys+';'+h.diasLogon+';'+name+'\n';});
  var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='KEV_'+name.replace(/[^a-z0-9]/gi,'_').substring(0,40)+'.csv';a.click();
};

window._kevFilterDash=function(vulnName){
  // Switch to dashboard and apply search filter
  var t=document.querySelector('[data-view=dashboard]');if(t)t.click();
  setTimeout(function(){
    var s=document.getElementById('sIn');
    if(s){s.value=vulnName.substring(0,40);s.dispatchEvent(new Event('input'));}
    // Scroll to table
    var tbl=document.getElementById('tabVuP');
    if(tbl){
      var tabBtn=document.getElementById('tabVu');
      if(tabBtn)tabBtn.click();
      setTimeout(function(){tbl.scrollIntoView({behavior:'smooth',block:'start'});},200);
    }
  },300);
};


