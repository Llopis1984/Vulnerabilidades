// ══════════════════════════════════════════════════════════════════════════════
// UTILS — Funciones compartidas entre todos los módulos
// ══════════════════════════════════════════════════════════════════════════════

// ── Shared state namespace ──
window.VD = window.VD || {};

// ── Normalization ──
function normEnv(e){return(e||'Desconocido').replace(/^Endpoint-/i,'').trim().normalize('NFD').replace(/[\u0300-\u036f]/g,'');}

// ── CSV parsing helpers (also duplicated in Worker) ──
function parseCVEs(str){ return (str||'').split('|').map(function(s){return s.trim();}).filter(function(s){return /^CVE-/i.test(s);}); }
function detectSep(h){var sc=0,cc=0,q=false;for(var i=0;i<h.length;i++){var c=h[i];if(c==='"'){q=!q;continue;}if(!q){if(c===';')sc++;else if(c===',')cc++;}}return sc>=cc?';':',';}
function parseCsv(text){
  var lines=text.split(/\r?\n/).filter(function(l){return l.trim();});if(lines.length<2)return[];var sep=detectSep(lines[0]);
  var hdr=splitQ(lines[0],sep).map(function(h){return h.trim().toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g,"");});
  var idx={vuln:fi2(hdr,'nombre vulnerabilidad'),host:fi2(hdr,'hostname'),ent:fi2(hdr,'entorno l2'),fesc:fi2(hdr,'fecha ultimo escaneo'),ead:fi2(hdr,'estado ad'),dlog:fi2(hdr,'dias logon'),res:fi2(hdr,'results'),sol:fi2(hdr,'solucion'),nvpr:fi2(hdr,'nivel vpr'),
    cve:fi2(hdr,'cve'),fpub:fi2(hdr,'fecha publicacion'),fdet:fi2(hdr,'fecha deteccion'),fultdet:fi2(hdr,'fecha ultima deteccion'),fincump:fi2(hdr,'fecha incumplimiento'),estdet:fi2(hdr,'estado deteccion'),qid:fi2(hdr,'qid')};
  if(idx.host<0){var i2={host:fi2(hdr,'hostname'),fesc:fi2(hdr,'fecha ultimo escaneo'),dq:fi2(hdr,'dias qualys'),ead:fi2(hdr,'estado ad'),dlog:fi2(hdr,'dias logon')};
    if(i2.host>=0){return lines.slice(1).filter(function(l){return splitQ(l,sep).length>=5;}).map(function(l){var c=splitQ(l,sep);return{vulnName:'General',hostname:g(c,i2.host),entorno:'Desconocido',fechaEsc:g(c,i2.fesc),estadoAD:g(c,i2.ead)||'SIN ESTADO',diasLogon:parseInt(g(c,i2.dlog))||0,results:'',solucion:'',nivelVPR:'',diasQualys:parseInt(g(c,i2.dq))||0,cves:'',fechaPub:'',fechaDet:'',fechaUltDet:'',fechaIncump:'',estadoDet:'',qid:''};});}}
  var rows=[];for(var i=1;i<lines.length;i++){var c=splitQ(lines[i],sep);if(c.length<5)continue;
    rows.push({vulnName:g(c,idx.vuln),hostname:g(c,idx.host),entorno:g(c,idx.ent),fechaEsc:g(c,idx.fesc),estadoAD:g(c,idx.ead)||'SIN ESTADO',diasLogon:parseInt(g(c,idx.dlog))||0,results:g(c,idx.res),solucion:g(c,idx.sol),nivelVPR:g(c,idx.nvpr),
      cves:g(c,idx.cve),fechaPub:g(c,idx.fpub),fechaDet:g(c,idx.fdet),fechaUltDet:g(c,idx.fultdet),fechaIncump:g(c,idx.fincump),estadoDet:g(c,idx.estdet),qid:g(c,idx.qid)});}return rows;
}
function fi2(h,n){var nm=n.normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase();return h.findIndex(function(x){return x.includes(nm);});}
function g(c,i){return i>=0&&i<c.length?c[i].trim():'';}
function splitQ(line,sep){var r=[],c='',q=false;for(var i=0;i<line.length;i++){var ch=line[i];if(q){if(ch==='"'){if(i+1<line.length&&line[i+1]==='"'){c+='"';i++;}else q=false;}else c+=ch;}else{if(ch==='"')q=true;else if(ch===sep){r.push(c);c='';}else c+=ch;}}r.push(c);return r;}

// ── Date helpers ──
function pDate(s){if(!s)return null;var m=s.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/);return m?new Date(+m[3],m[2]-1,+m[1]):null;}
function dDiff(d){if(!d)return 999;var n=new Date();n.setHours(0,0,0,0);return Math.max(0,Math.floor((n-d)/864e5));}

// ── Entorno icon helper ──
function getEnvIcon(eName) {
  var e = (eName||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
  if(e.includes('apple') || e.includes('mac')) return '<svg class="dxc-ico" style="width:14px;height:14px;margin-bottom:-2px;fill:currentColor"><use href="#ico-apple"/></svg>';
  if(e.includes('virtual') || e.includes('vm')) return '<svg class="dxc-ico" style="width:14px;height:14px;margin-bottom:-2px;fill:currentColor"><use href="#ico-windows"/></svg>';
  if(e.includes('cajero') || e.includes('atm')) return '<span class="material-icons-round" style="font-size:16px;vertical-align:-3px">local_atm</span>';
  if(e.includes('actualizador') || e.includes('libreta')) return '<span class="material-icons-round" style="font-size:16px;vertical-align:-3px">published_with_changes</span>';
  if(e.includes('portatil') || e.includes('laptop')) return '<span class="material-icons-round" style="font-size:16px;vertical-align:-3px">laptop_mac</span>';
  if(e.includes('fijo') || e.includes('desktop')) return '<span class="material-icons-round" style="font-size:16px;vertical-align:-3px">desktop_windows</span>';
  return '<span class="material-icons-round" style="font-size:16px;vertical-align:-3px">devices</span>';
}

// ── KEV stamp — marks isKEV on all raw rows once ──
window.stampKEV = function(){
  var raw = window._raw; if(!raw || !raw.length) return;
  var kevSet = window._kevSet;
  var hasKEV = kevSet && kevSet.size > 0;
  var kevVulns = {};
  var kevHostSet = new Set();
  raw.forEach(function(r){
    var cves = r._parsedCves || parseCVEs(r.cves);
    if(hasKEV){
      var matched = cves.filter(function(c){return kevSet.has(c);});
      r.isKEV = matched.length > 0;
      r.kevCves = matched;
      if(r.isKEV){
        kevHostSet.add(r.hostname);
        if(!kevVulns[r.vulnName]){
          kevVulns[r.vulnName] = {hosts:new Set(),kevCves:new Set(),vpr:r.nivelVPR,sol:r.solucion,cves:new Set()};
        }
        kevVulns[r.vulnName].hosts.add(r.hostname);
        matched.forEach(function(c){kevVulns[r.vulnName].kevCves.add(c);});
        cves.forEach(function(c){kevVulns[r.vulnName].cves.add(c);});
      }
    } else {
      r.isKEV = false;
      r.kevCves = [];
    }
  });
  window._kevVulnsCache = Object.entries(kevVulns);
  window._kevHostSetCache = kevHostSet;
};

// ── Badge helper ──
function bdg(c,t){return '<span class="bd '+c+'">'+t+'</span>';}
function gR(d){if(d.estadoAD==='HABILITADO'&&d.diasQualys>15&&d.diasLogon>15)return 'critico';if(d.diasQualys>15||d.diasLogon>15)return 'atencion';return 'ok';}

// ══════════════════════════════════════════════════════════════════════════════
// SMART CACHE — localStorage con TTL + precarga al abrir el HTML
// ══════════════════════════════════════════════════════════════════════════════
var _CACHE_KEYS = {
  kev:  'vuln_kev_cache_v1',
  epss: 'vuln_epss_cache_v1',
};
var _CACHE_TTL = {
  kev:  6  * 60 * 60 * 1000,
  epss: 12 * 60 * 60 * 1000,
};

function _cacheGet(key){
  try{ var r=localStorage.getItem(_CACHE_KEYS[key]); return r?JSON.parse(r):null; }
  catch(e){ return null; }
}
function _cacheSet(key, dataStr, meta){
  try{
    localStorage.setItem(_CACHE_KEYS[key], JSON.stringify({
      data: dataStr, timestamp: Date.now(), meta: meta||{}
    }));
  } catch(e){ console.warn('[CACHE] localStorage lleno:', e.message); }
}
function _cacheIsFresh(key){
  var c=_cacheGet(key);
  return c && (Date.now()-c.timestamp) < _CACHE_TTL[key];
}

async function _fetchCached(url, cacheKey, ttlMs){
  var cached = _cacheGet(cacheKey);
  var fresh  = cached && (Date.now()-cached.timestamp) < ttlMs;
  if(fresh){
    return {data: cached.data, fromCache:true, fresh:true};
  }
  try{
    var r = await _fetchTimeout(url, 20000);
    if(!r.ok) throw new Error('HTTP '+r.status);
    var text = await r.text();
    var changed = !cached || text !== cached.data;
    _cacheSet(cacheKey, text, {url:url, changed:changed});
    return {data: text, fromCache:false, fresh:false, changed:changed};
  } catch(e){
    if(cached){
      return {data: cached.data, fromCache:true, fresh:false, stale:true};
    }
    throw e;
  }
}

function _fetchTimeout(url, ms){
  var ctrl = new AbortController();
  var tid  = setTimeout(function(){ ctrl.abort(); }, ms||20000);
  return fetch(url, {signal: ctrl.signal}).finally(function(){ clearTimeout(tid); });
}
