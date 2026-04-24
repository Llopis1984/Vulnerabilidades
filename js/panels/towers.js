// ══════════════════════════════════════════════════════════════════════════════
// TOWERS — Clasificación de vulnerabilidades por torre responsable
// Motor en 3 capas: hostname → reglas regex (vulnName/results/solucion) → IA
// ══════════════════════════════════════════════════════════════════════════════
(function(){

  var TOWERS = [
    'Wintel','Unix','Storage & Backup','Hermes','Oracle','Ms-Sql',
    'Web Server','Apps Server','Mgt','Itsm','Network','Product Operation',
    'Swift','Ticketing & Reporting','M360','Device Management','M365','Citrix',
    'Sin clasificar'
  ];

  // ── Reglas por defecto ──────────────────────────────────────────────────────
  // Orden importa: primera que matchea gana. Específicas primero, genéricas al final.
  var DEFAULT_RULES = [
    // Citrix (muy específico — antes que Windows genérico)
    { rx: /\bcitrix\b|xenapp|xendesktop|netscaler|storefront|virtual apps.?and.?desktops|vda\b/i, torre: 'Citrix', conf: 'alta' },

    // Swift (pagos)
    { rx: /\bswift\b|alliance access|alliance gateway|swiftnet/i, torre: 'Swift', conf: 'alta' },

    // Bases de datos — antes que "Oracle" genérico
    { rx: /sql server|mssql|microsoft sql/i, torre: 'Ms-Sql', conf: 'alta' },
    { rx: /oracle database|oracle db|oracle server|\boracle\b.*\b(database|db|rdbms|client|listener|tns)\b|pl\/sql/i, torre: 'Oracle', conf: 'alta' },

    // Web Server
    { rx: /apache http|apache2|apache\/2|\bhttpd\b|\bnginx\b|tomcat|microsoft iis|\biis\b|lighttpd/i, torre: 'Web Server', conf: 'alta' },

    // Apps Server
    { rx: /weblogic|websphere|\bjboss\b|wildfly|glassfish|node\.?js|\bnodejs\b|express\.?js/i, torre: 'Apps Server', conf: 'alta' },

    // Storage & Backup
    { rx: /netapp|\bemc\b|dell emc|isilon|powermax|powerscale|unity\s*xt|commvault|veeam|rubrik|netbackup|tsm backup|tivoli storage|data domain|avamar|brocade|nas\b|san\s*switch/i, torre: 'Storage & Backup', conf: 'alta' },

    // Network (routers/firewalls/switches)
    { rx: /\bcisco\b|\bf5\b|big-?ip|fortinet|fortigate|palo alto|panos|pan-os|juniper|junos|checkpoint|check point|sonicwall|aruba|ruckus|pfsense|mikrotik/i, torre: 'Network', conf: 'alta' },

    // Mgt (virtualización y gestión)
    { rx: /vmware|vcenter|esxi|vsphere|horizon view|nsx\b|vrops|vrealize|hyper-?v|proxmox/i, torre: 'Mgt', conf: 'alta' },

    // M365 (cloud Microsoft — solo referencias cloud explícitas; "Office 365 Suite" sin más va a ofimática/Device)
    { rx: /exchange online|sharepoint online|onedrive for business|\bm365\b|azure ad|entra id|defender for (office|endpoint|cloud)|intune\b|microsoft graph/i, torre: 'M365', conf: 'alta' },

    // ITSM / Ticketing
    { rx: /servicenow|\bbmc\b|remedy|jira|service desk|zendesk|freshservice/i, torre: 'Itsm', conf: 'alta' },
    { rx: /power bi|tableau|qlik|\bsplunk\b|elastic(search)?|grafana|kibana/i, torre: 'Ticketing & Reporting', conf: 'media' },

    // Hermes (bus corporativo típico — ajustar si el cliente usa otro término)
    { rx: /\bhermes\b|websphere mq|ibm mq|rabbitmq|\bkafka\b|tibco|activemq/i, torre: 'Hermes', conf: 'alta' },

    // M360 (monitorización — convención del cliente)
    { rx: /\bm360\b|microfocus|open ?text.*operations|obm\b|patrol\b|sitescope|nagios|zabbix|prtg|solarwinds/i, torre: 'M360', conf: 'media' },

    // Exchange on-premise, SharePoint on-premise → Wintel (no M365)
    { rx: /exchange server|microsoft exchange(?!\s+online)|sharepoint(?!\s+online)/i, torre: 'Wintel', conf: 'alta' },

    // SO servidor — Windows Server y componentes
    { rx: /windows server|server\s+20(08|12|16|19|22|25)|\bwsus\b|\bdomain controller\b|active directory|\brdp\b.*server|print spooler|dns server|dhcp server/i, torre: 'Wintel', conf: 'alta' },

    // SO servidor — Unix/Linux
    { rx: /red ?hat|\brhel\b|centos|rocky linux|alma linux|ubuntu server|debian|\bsuse\b|\bsles\b|oracle linux|\baix\b|\bsolaris\b|\bhp-?ux\b|\bopenssh\b|\bbind\b|sendmail|postfix|\bsudo\b/i, torre: 'Unix', conf: 'alta' },

    // Java (en servidor → Apps Server; en PC sería Device, pero priorizamos Apps Server si es el runtime)
    { rx: /\bjava\s*se\b|java runtime|\bjre\b|\bjdk\b|oracle java/i, torre: 'Apps Server', conf: 'media' },

    // Puesto de trabajo (paquetes ofimática / navegadores / lectores / diseño / dev tools)
    { rx: /microsoft office|outlook|word|excel|powerpoint|onenote|visio|access\b|publisher|\bteams\b(?!.*server)|microsoft edge|google chrome|chromium|mozilla firefox|\bfirefox\b|acrobat reader|adobe acrobat|adobe reader|adobe flash|adobe (illustrator|photoshop|indesign|premiere|after effects|lightroom|bridge|animate|xd)\b|\b7-?zip\b|\bwinrar\b|greenshot|\bvlc\b|\bzoom\b|notepad\+\+|\bputty\b|\bgimp\b|visual studio code|\bvscode\b|microsoft visual studio(?!.*\bserver\b)/i, torre: 'Device Management', conf: 'alta' },

    // Windows 10/11 cliente → Device Management
    { rx: /windows\s*1[01]\b|windows\s*7\b|windows\s*8\b/i, torre: 'Device Management', conf: 'alta' },

    // Microsoft Windows genérico (parche mensual, sin versión específica) → Wintel por defecto
    // (se refina con classifyHostType si detectamos PC)
    { rx: /microsoft windows|windows security update|kb\d{6,8}/i, torre: 'Wintel', conf: 'media' },

    // .NET Framework / .NET Core updates — componente de Windows (se refina a Device en PCs)
    { rx: /microsoft\s*\.?net|\bdotnet\b|\.net\s+(framework|core|security)/i, torre: 'Wintel', conf: 'media' },

    // Product Operation (último recurso para productos de negocio/SaaS no técnicos)
    { rx: /\bsap\b|salesforce|workday|\bservicenow\b/i, torre: 'Product Operation', conf: 'media' },

    // Dell/HP/Intel firmware → Wintel en servidor, Device en PC (se desambigua por hostType)
    { rx: /\bdell\b.*(bios|firmware|client|security)|\bhp\b.*(bios|firmware|ilo)|\bintel\b.*(driver|firmware|amt)/i, torre: 'Wintel', conf: 'media' }
  ];

  function _loadRulesOverride(){
    try {
      var raw = localStorage.getItem('tower_rules_override_v1');
      if(!raw) return null;
      var arr = JSON.parse(raw);
      if(!Array.isArray(arr)) return null;
      return arr.map(function(r){ return { rx: new RegExp(r.rx, 'i'), torre: r.torre, conf: r.conf||'alta' }; });
    } catch(e){ return null; }
  }
  function _saveRulesOverride(arr){
    try {
      var safe = arr.map(function(r){ return { rx: (r.rx instanceof RegExp ? r.rx.source : r.rx), torre: r.torre, conf: r.conf }; });
      localStorage.setItem('tower_rules_override_v1', JSON.stringify(safe));
    } catch(e){}
  }
  function _clearRulesOverride(){ try { localStorage.removeItem('tower_rules_override_v1'); } catch(e){} }

  function _getActiveRules(){ return _loadRulesOverride() || DEFAULT_RULES; }

  // ── Capa 1: tipo de dispositivo ──────────────────────────────────────────────
  // Quita tildes para que "Ofimática" → "Ofimatica"
  function _stripAccents(s){ return (s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,''); }

  function classifyHostType(hostname, entorno){
    var h = (hostname||'').toUpperCase();
    var e = _stripAccents(entorno||'').toUpperCase();
    // VDI / Citrix — hostname o entorno
    if(/^(VDI|CTX|XD|XA|VDIW|VDIL|VIRT)[-_0-9]/.test(h) || /\bVDI\b|\bCITRIX\b|\bVIRTUAL\b|\bTHIN\s*CLIENT\b/.test(e)) return 'vdi';
    // PC / workstation / portátil / cajero / actualizador — convenciones reales del cliente
    // Hostnames: FIJO-*, MOVIL-*, PC-*, NB-*, WKS-*, LAP-*, DESK-*, CLI-*, WS-*, DT-*, PORT-*, CAJERO-*, ATM-*, UPD-*, ACT-*
    if(/^(PC|NB|WKS|LAP|DESK|CLI|WS|DT|PORT|FIJO|MOVIL|SOBREMESA|CAJ|CAJERO|ATM|UPD|ACT|ACTUAL|KIOSKO|KIOSK)[-_0-9]/.test(h)) return 'pc';
    // Entorno L2/L3: Fijo, Movil, Portatil, Puesto, Workplace, Device, Endpoint, Ofimatica, Sobremesa, Cajero, Actualizador
    if(/\b(PUESTO|WORKPLACE|DEVICE|ENDPOINT|OFIMATICA|FIJO|MOVIL|PORTATIL|SOBREMESA|USUARIO|CAJERO|CAJEROS|ATM|ACTUALIZADOR|ACTUALIZADORES|KIOSKO|KIOSK)\b/.test(e)) return 'pc';
    // Servidor explícito
    if(/^(SRV|SVR|SRVWIN|SRVLIN|SRVUX|UX|AIX|LNX|WIN|S|SR|SER)[-_0-9]/.test(h) || /\b(SERVIDOR|SERVER|SRV|DATACENTER|CPD|INFRAESTRUCTURA)\b/.test(e)) return 'server';
    return 'unknown';
  }

  // ── Capa 2: reglas sobre el texto de la vuln ─────────────────────────────────
  function _applyRules(text){
    var rules = _getActiveRules();
    for(var i=0; i<rules.length; i++){
      if(rules[i].rx.test(text)) return { torre: rules[i].torre, conf: rules[i].conf, idx: i };
    }
    return null;
  }

  // ── Clasificación principal ──────────────────────────────────────────────────
  function classifyRow(row){
    if(!row) return { torre: 'Sin clasificar', conf: 'baja', fuente: 'none' };

    var hostType = classifyHostType(row.hostname, row.entorno);

    // VDI → Citrix SIEMPRE (la vuln aplica sobre la imagen del VDI)
    if(hostType === 'vdi') return { torre: 'Citrix', conf: 'alta', fuente: 'host' };

    // PC/portátil/cajero/actualizador → SIEMPRE Device Management.
    // El tipo de dispositivo prevalece sobre la vulnerabilidad. Nunca un PC pertenece a Wintel,
    // Oracle, Apps Server, etc. aunque la vuln sea de un producto de servidor.
    if(hostType === 'pc') return { torre: 'Device Management', conf: 'alta', fuente: 'host' };

    // Servidor o desconocido → manda la regla sobre el texto de la vulnerabilidad
    var text = (row.vulnName||'') + ' || ' + (row.results||'') + ' || ' + (row.solucion||'');
    var ruleHit = _applyRules(text);
    if(ruleHit) return { torre: ruleHit.torre, conf: ruleHit.conf, fuente: 'rule' };

    return { torre: 'Sin clasificar', conf: 'baja', fuente: 'none' };
  }

  // ── Caché IndexedDB por vulnName ─────────────────────────────────────────────
  var _memCache = {};

  function _normVulnKey(v){ return (v||'').toLowerCase().trim().substring(0, 240); }

  async function getCachedTower(vulnName){
    var k = _normVulnKey(vulnName); if(!k) return null;
    if(_memCache[k]) return _memCache[k];
    if(typeof VDB !== 'undefined' && VDB.getTowerCache){
      var r = await VDB.getTowerCache(k);
      if(r){ _memCache[k] = r; return r; }
    }
    return null;
  }
  async function setCachedTower(vulnName, entry){
    var k = _normVulnKey(vulnName); if(!k) return;
    _memCache[k] = entry;
    if(typeof VDB !== 'undefined' && VDB.setTowerCache){
      try { await VDB.setTowerCache(k, entry); } catch(e){}
    }
  }

  // ── Capa 3: IA (Gemini) ─────────────────────────────────────────────────────
  async function batchClassifyAI(vulnNames, onProgress){
    if(!window._geminiAsk || !window._geminiHasKey()){
      throw new Error('NO_GEMINI_KEY');
    }
    var unique = [...new Set(vulnNames.filter(Boolean))];
    var results = {};
    // Primero caché
    for(var i=0; i<unique.length; i++){
      var cached = await getCachedTower(unique[i]);
      if(cached){ results[unique[i]] = cached; }
    }
    var pending = unique.filter(function(v){ return !results[v]; });
    if(!pending.length) return results;

    var CHUNK = 40;
    var total = pending.length, done = 0;
    for(var c=0; c<pending.length; c+=CHUNK){
      var chunk = pending.slice(c, c+CHUNK);
      var list = chunk.map(function(v,i){ return (i+1)+'. '+v; }).join('\n');
      var sys = 'Eres un experto en infraestructura IT de banca. Clasifica cada vulnerabilidad en UNA de estas torres responsables exactas: '
        + TOWERS.filter(function(t){return t!=='Sin clasificar';}).join(' | ')
        + '. Usa el nombre del software/producto afectado como señal principal. '
        + 'Si no hay suficiente información, responde "Sin clasificar". Devuelve SIEMPRE JSON.';
      var prompt = 'Clasifica estas '+chunk.length+' vulnerabilidades:\n\n'+list+'\n\n'
        + 'Responde con un array JSON. Cada elemento {"n": <número>, "torre": "<torre exacta>", "conf": "alta|media|baja"}.';
      try {
        var raw = await window._geminiAsk(prompt, sys, {
          json: true, temperature: 0.2, maxOutputTokens: 4096,
          responseSchema: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                n: { type: 'integer' },
                torre: { type: 'string', enum: TOWERS },
                conf: { type: 'string', enum: ['alta','media','baja'] }
              },
              required: ['n','torre','conf']
            }
          }
        });
        var arr = JSON.parse(raw);
        arr.forEach(function(item){
          var idx = (item.n|0) - 1;
          if(idx>=0 && idx<chunk.length){
            var entry = { torre: item.torre, conf: item.conf, fuente: 'ai', ts: Date.now() };
            results[chunk[idx]] = entry;
            setCachedTower(chunk[idx], entry);
          }
        });
      } catch(e){
        console.warn('[Towers] IA chunk error:', e);
      }
      done += chunk.length;
      if(onProgress) onProgress(done, total);
    }
    return results;
  }

  // ── Enriquecer filas crudas con torre ───────────────────────────────────────
  window._enrichRowWithTower = function(r){
    var cls = classifyRow(r);
    r.torre = cls.torre;
    r.torreConfianza = cls.conf;
    r.torreFuente = cls.fuente;
    return cls;
  };

  window._applyCachedTowerOverrides = async function(){
    // Después de enriquecimiento sync, aplicar aciertos de IA que haya en caché
    if(!window._raw) return 0;
    var vulns = [...new Set(window._raw.map(function(r){return r.vulnName;}).filter(Boolean))];
    var hits = 0;
    for(var i=0; i<vulns.length; i++){
      var c = await getCachedTower(vulns[i]);
      if(c){
        window._raw.forEach(function(r){
          if(r.vulnName===vulns[i] && (r.torreFuente==='none'||r.torreFuente==='rule' && c.fuente==='ai')){
            r.torre = c.torre; r.torreConfianza = c.conf; r.torreFuente = c.fuente;
            hits++;
          }
        });
      }
    }
    return hits;
  };

  window._towersClassifyPendingAI = async function(){
    var btn = document.getElementById('towersAIBtn');
    var status = document.getElementById('towersAIStatus');
    if(!window._raw || !window._raw.length){
      if(status) status.textContent = 'Carga y analiza un CSV primero.';
      return;
    }
    if(!window._geminiHasKey()){
      window._geminiOpenKeyModal(function(){ window._towersClassifyPendingAI(); });
      return;
    }
    // Priorizar vulns sin clasificar; si no hay, caer a las de confianza media (que no sean por host directo)
    var pending = [...new Set(window._raw.filter(function(r){return r.torre==='Sin clasificar'||r.torreConfianza==='baja';}).map(function(r){return r.vulnName;}).filter(Boolean))];
    if(!pending.length){
      pending = [...new Set(window._raw.filter(function(r){return r.torreConfianza==='media' && r.torreFuente==='rule';}).map(function(r){return r.vulnName;}).filter(Boolean))];
      if(status) status.textContent = pending.length ? 'Sin pendientes claros; refinando '+pending.length+' con confianza media…' : 'Todas las vulnerabilidades tienen ya una torre con alta confianza.';
      if(!pending.length) return;
    }
    if(btn){ btn.disabled = true; btn.innerHTML = '<span class="material-icons-round" style="font-size:14px">hourglass_top</span> Clasificando '+pending.length+'…'; }
    try {
      var out = await batchClassifyAI(pending, function(done,total){
        if(status) status.textContent = 'Procesando '+done+' / '+total+'…';
      });
      // Aplicar al _raw
      var applied = 0;
      window._raw.forEach(function(r){
        var o = out[r.vulnName];
        if(o){ r.torre = o.torre; r.torreConfianza = o.conf; r.torreFuente = 'ai'; applied++; }
      });
      if(status) status.textContent = 'IA clasificó '+applied+' filas.';
      window.renderTowersPanel();
    } catch(e){
      if(status) status.textContent = 'Error IA: '+(e.message||e);
    } finally {
      if(btn){ btn.disabled = false; btn.innerHTML = '<span class="material-icons-round" style="font-size:14px">auto_awesome</span> Clasificar pendientes con IA'; }
    }
  };

  // ── Export CSV por torre ────────────────────────────────────────────────────
  window._towersExportCSV = function(){
    if(!window._raw) return;
    var rows = ['Torre,Confianza,Fuente,Hostname,Entorno,Vulnerabilidad,CVE,VPR,Dias Qualys'];
    window._raw.forEach(function(r){
      var cell = function(s){ s=String(s==null?'':s); return /[,"\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s; };
      rows.push([r.torre,r.torreConfianza,r.torreFuente,r.hostname,r.entorno,r.vulnName,r.cves,r.nivelVPR,r.diasQualys||0].map(cell).join(','));
    });
    var blob = new Blob([rows.join('\n')],{type:'text/csv'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vulnerabilidades_por_torre_'+new Date().toISOString().slice(0,10)+'.csv';
    a.click();
  };

  // ── Modal de reglas editables ────────────────────────────────────────────────
  window._towersOpenRulesModal = function(){
    var existing = document.getElementById('towersRulesModal'); if(existing) existing.remove();
    var rules = _getActiveRules();
    var modal = document.createElement('div');
    modal.id = 'towersRulesModal';
    modal.style.cssText = 'position:fixed;inset:0;background:var(--modal-bg,rgba(0,0,0,.45));z-index:2000;display:flex;align-items:center;justify-content:center;padding:20px';
    var rowsHtml = rules.map(function(r,i){
      return '<tr>'
        +'<td><input data-i="'+i+'" data-k="rx" value="'+(r.rx instanceof RegExp?r.rx.source:r.rx).replace(/"/g,'&quot;')+'" style="width:100%;font-family:Monaco,monospace;font-size:.72rem;padding:4px 6px;border:1px solid var(--ol);border-radius:6px"></td>'
        +'<td><select data-i="'+i+'" data-k="torre" style="font-size:.72rem;padding:4px;border:1px solid var(--ol);border-radius:6px">'+TOWERS.map(function(t){return '<option'+(t===r.torre?' selected':'')+'>'+t+'</option>';}).join('')+'</select></td>'
        +'<td><select data-i="'+i+'" data-k="conf" style="font-size:.72rem;padding:4px;border:1px solid var(--ol);border-radius:6px">'+['alta','media','baja'].map(function(c){return '<option'+(c===r.conf?' selected':'')+'>'+c+'</option>';}).join('')+'</select></td>'
        +'<td><button onclick="window._towersDeleteRule('+i+')" style="background:none;border:none;color:var(--err);cursor:pointer"><span class="material-icons-round" style="font-size:16px">delete</span></button></td>'
        +'</tr>';
    }).join('');
    modal.innerHTML =
      '<div style="background:var(--s1);border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.25);max-width:960px;width:100%;max-height:90vh;overflow:hidden;display:flex;flex-direction:column">'
      +'<div style="padding:16px 22px;border-bottom:1px solid var(--olv);display:flex;align-items:center;gap:10px">'
      +'<span class="material-icons-round" style="color:var(--p)">rule</span>'
      +'<div style="flex:1"><div style="font-family:var(--fd);font-weight:700">Reglas de clasificación por torre</div>'
      +'<div style="font-size:.70rem;color:var(--t2)">Regex sobre <code>vulnName + results + solucion</code>. Orden = prioridad. Se guarda en tu navegador.</div></div>'
      +'<button onclick="document.getElementById(\'towersRulesModal\').remove()" style="background:none;border:none;cursor:pointer;color:var(--t2)"><span class="material-icons-round">close</span></button>'
      +'</div>'
      +'<div style="overflow:auto;padding:14px 22px"><table id="towersRulesTable" style="width:100%;border-collapse:collapse;font-size:.74rem">'
      +'<thead><tr style="background:var(--s2)"><th style="text-align:left;padding:6px 8px;font-size:.65rem;color:var(--t2);text-transform:uppercase">Regex</th><th style="text-align:left;padding:6px 8px;font-size:.65rem;color:var(--t2);text-transform:uppercase">Torre</th><th style="text-align:left;padding:6px 8px;font-size:.65rem;color:var(--t2);text-transform:uppercase">Confianza</th><th></th></tr></thead>'
      +'<tbody>'+rowsHtml+'</tbody></table></div>'
      +'<div style="padding:12px 22px;border-top:1px solid var(--olv);display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap">'
      +'<button onclick="window._towersResetRules()" style="padding:8px 14px;border-radius:18px;border:1px solid var(--err);color:var(--err);background:transparent;cursor:pointer;font-size:.74rem">Restaurar por defecto</button>'
      +'<button onclick="window._towersAddRule()" style="padding:8px 14px;border-radius:18px;border:1px solid var(--ol);background:var(--s1);cursor:pointer;font-size:.74rem">+ Añadir regla</button>'
      +'<button onclick="window._towersSaveRules()" style="padding:8px 18px;border-radius:18px;border:none;background:var(--p);color:#fff;cursor:pointer;font-weight:600;font-size:.74rem">Guardar y re-clasificar</button>'
      +'</div></div>';
    document.body.appendChild(modal);
  };
  window._towersAddRule = function(){
    var tbody = document.querySelector('#towersRulesTable tbody'); if(!tbody) return;
    var rules = _collectRulesFromModal();
    rules.push({ rx: '', torre: 'Sin clasificar', conf: 'media' });
    _saveRulesOverride(rules);
    window._towersOpenRulesModal();
  };
  window._towersDeleteRule = function(i){
    var rules = _collectRulesFromModal();
    rules.splice(i,1);
    _saveRulesOverride(rules);
    window._towersOpenRulesModal();
  };
  window._towersResetRules = function(){
    if(!confirm('¿Restaurar las reglas por defecto? Se pierde lo editado.')) return;
    _clearRulesOverride();
    document.getElementById('towersRulesModal').remove();
    _reclassifyAll();
    window.renderTowersPanel();
  };
  window._towersSaveRules = function(){
    var rules = _collectRulesFromModal().filter(function(r){return r.rx;});
    _saveRulesOverride(rules);
    document.getElementById('towersRulesModal').remove();
    _reclassifyAll();
    window.renderTowersPanel();
  };
  function _collectRulesFromModal(){
    var tbody = document.querySelector('#towersRulesTable tbody'); if(!tbody) return _getActiveRules().map(function(r){return {rx:r.rx.source||r.rx,torre:r.torre,conf:r.conf};});
    var rows = tbody.querySelectorAll('tr');
    var arr = [];
    rows.forEach(function(tr){
      var rx = tr.querySelector('[data-k=rx]').value;
      var torre = tr.querySelector('[data-k=torre]').value;
      var conf = tr.querySelector('[data-k=conf]').value;
      arr.push({ rx: rx, torre: torre, conf: conf });
    });
    return arr;
  }
  function _reclassifyAll(){
    if(!window._raw) return;
    window._raw.forEach(function(r){ window._enrichRowWithTower(r); });
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // RENDER PRINCIPAL
  // ══════════════════════════════════════════════════════════════════════════════
  window.renderTowersPanel = function(){
    var ct = document.getElementById('ct-towers');
    if(!ct) return;
    if(!window._raw || !window._raw.length){
      ct.innerHTML = '<div style="padding:40px;text-align:center;color:var(--t2)">Carga un CSV primero para ver la clasificación por torre.</div>';
      return;
    }

    // Agrupar por torre
    var byTower = {};
    var totalRows = 0, unclassified = 0, lowConf = 0;
    window._raw.forEach(function(r){
      var t = r.torre || 'Sin clasificar';
      if(!byTower[t]) byTower[t] = { vulns: 0, kevs: 0, slaBreached: 0, hosts: new Set(), vulnNames: new Set(), sampleRows: [] };
      byTower[t].vulns++;
      if(r.isKEV) byTower[t].kevs++;
      if(r.diasQualys>15) byTower[t].slaBreached++;
      if(r.hostname) byTower[t].hosts.add(r.hostname);
      if(r.vulnName) byTower[t].vulnNames.add(r.vulnName);
      if(byTower[t].sampleRows.length<50) byTower[t].sampleRows.push(r);
      totalRows++;
      if(t==='Sin clasificar') unclassified++;
      if(r.torreConfianza==='baja') lowConf++;
    });

    var entries = Object.entries(byTower).sort(function(a,b){ return b[1].vulns - a[1].vulns; });

    var html = '<div style="max-width:1440px;margin:0 auto;padding:24px 28px">';

    // Header
    html += '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">'
      +'<div><div style="font-family:var(--fd);font-size:1.15rem;font-weight:700;display:flex;align-items:center;gap:10px;letter-spacing:-.3px"><span class="material-icons-round" style="color:var(--p);font-size:24px">groups</span>Vulnerabilidades por Torre</div>'
      +'<div style="font-size:.73rem;color:var(--t2);margin-top:4px">'+totalRows+' vulnerabilidades · '+entries.length+' torres · '+unclassified+' sin clasificar · '+lowConf+' con confianza baja</div></div>'
      +'<div style="display:flex;gap:8px;flex-wrap:wrap">'
      +'<button onclick="window._towersOpenRulesModal()" style="display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:18px;border:1px solid var(--ol);background:var(--s1);cursor:pointer;font-size:.74rem"><span class="material-icons-round" style="font-size:14px">rule</span> Editar reglas</button>'
      +'<button id="towersAIBtn" onclick="window._towersClassifyPendingAI()" style="display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:18px;border:none;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;cursor:pointer;font-size:.74rem;font-weight:600"><span class="material-icons-round" style="font-size:14px">auto_awesome</span> Clasificar pendientes con IA</button>'
      +'<button onclick="window._towersExportCSV()" style="display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:18px;border:1px solid var(--p);color:var(--p);background:transparent;cursor:pointer;font-size:.74rem"><span class="material-icons-round" style="font-size:14px">download</span> Exportar CSV</button>'
      +'</div></div>'
      +'<div id="towersAIStatus" style="font-size:.72rem;color:var(--t2);margin-bottom:14px;min-height:1em"></div>';

    // Tarjetas por torre
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-bottom:24px">';
    entries.forEach(function(e){
      var name = e[0], data = e[1];
      var kevColor = data.kevs>0 ? 'var(--err)' : 'var(--t2)';
      var unclassTag = name==='Sin clasificar' ? 'style="border:1px dashed var(--warn)"' : '';
      html += '<div '+unclassTag+' onclick="window._towersDrill(\''+name.replace(/\'/g,"\\'")+'\')" style="background:var(--s1);border-radius:12px;box-shadow:var(--e1);padding:14px 16px;cursor:pointer;transition:transform .15s,box-shadow .15s" onmouseover="this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'var(--e2)\'" onmouseout="this.style.transform=\'none\';this.style.boxShadow=\'var(--e1)\'">'
        +'<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px">'
        +'<div style="font-family:var(--fd);font-weight:700;font-size:.92rem">'+name+'</div>'
        +'<span style="background:var(--s2);color:var(--t2);font-size:.64rem;padding:2px 8px;border-radius:10px">'+data.hosts.size+' host'+(data.hosts.size!==1?'s':'')+'</span>'
        +'</div>'
        +'<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;font-size:.68rem">'
        +'<div><div style="color:var(--t2);font-size:.6rem;text-transform:uppercase">Vulns</div><div style="font-weight:700;font-size:1.05rem">'+data.vulns+'</div></div>'
        +'<div><div style="color:var(--t2);font-size:.6rem;text-transform:uppercase">KEVs</div><div style="font-weight:700;font-size:1.05rem;color:'+kevColor+'">'+data.kevs+'</div></div>'
        +'<div><div style="color:var(--t2);font-size:.6rem;text-transform:uppercase">SLA 15d+</div><div style="font-weight:700;font-size:1.05rem;color:'+(data.slaBreached>0?'var(--warn)':'var(--t2)')+'">'+data.slaBreached+'</div></div>'
        +'</div></div>';
    });
    html += '</div>';

    // Zona drill
    html += '<div id="towersDrill"></div>';

    html += '</div>';
    ct.innerHTML = html;
  };

  // Estado del drill (para que el buscador filtre sin re-renderizar todo)
  var _drillState = { torre: null, search: '', activeTab: 'vulns' };

  window._towersDrill = function(torre){
    _drillState.torre = torre;
    _drillState.search = '';
    _drillState.activeTab = 'vulns';
    _renderDrill();
  };

  window._towersDrillSearch = function(v){
    _drillState.search = (v||'').toLowerCase();
    _renderDrillBody();
  };

  window._towersDrillTab = function(tab){
    _drillState.activeTab = tab;
    _drillState.search = '';
    _renderDrill();
  };

  window._towersGoToDashboard = function(torre){
    // Abre el dashboard principal con el filtro de torre aplicado
    if(window._setGlobalTower) window._setGlobalTower(torre);
    var selTower = document.getElementById('globalTowerSel');
    if(selTower) selTower.value = torre;
    var dashTab = document.querySelector('[data-view=dashboard]');
    if(dashTab) dashTab.click();
  };

  function _renderDrill(){
    var area = document.getElementById('towersDrill'); if(!area) return;
    var torre = _drillState.torre; if(!torre){ area.innerHTML=''; return; }
    var rows = window._raw.filter(function(r){return (r.torre||'Sin clasificar')===torre;});
    var hostSet = {}; rows.forEach(function(r){ if(r.hostname) hostSet[r.hostname] = 1; });
    var hostCount = Object.keys(hostSet).length;
    var uniqVulns = [...new Set(rows.map(function(r){return r.vulnName;}).filter(Boolean))].length;

    var html = '<div style="background:var(--s1);border-radius:12px;box-shadow:var(--e1);overflow:hidden;margin-top:6px">'
      // Header
      +'<div style="padding:12px 18px;border-bottom:1px solid var(--olv);display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
      +'<span class="material-icons-round" style="color:var(--p);font-size:18px">list_alt</span>'
      +'<div style="font-family:var(--fd);font-weight:700">'+torre+'</div>'
      +'<span style="color:var(--t2);font-size:.72rem">'+rows.length+' vulns · '+uniqVulns+' únicas · '+hostCount+' hosts</span>'
      +'<div style="flex:1"></div>'
      +'<button onclick="window._towersGoToDashboard(\''+torre.replace(/\'/g,"\\'")+'\')" style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:14px;border:1px solid var(--p);color:var(--p);background:transparent;font-size:.68rem;cursor:pointer" title="Abrir dashboard filtrado por '+torre+'"><span class="material-icons-round" style="font-size:14px">open_in_new</span> Ver en dashboard</button>'
      +'<button onclick="_drillState_close()" id="towersDrillClose" style="background:none;border:none;color:var(--t2);cursor:pointer;padding:4px"><span class="material-icons-round">close</span></button>'
      +'</div>'
      // Tabs + buscador
      +'<div style="padding:10px 18px;border-bottom:1px solid var(--olv);display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
      +'<div style="display:inline-flex;border:1px solid var(--ol);border-radius:14px;overflow:hidden;font-size:.72rem">'
      +'<button id="drillTabVulns" onclick="window._towersDrillTab(\'vulns\')" class="lb '+(_drillState.activeTab==='vulns'?'active':'')+'" style="padding:6px 14px;border:none;background:'+(_drillState.activeTab==='vulns'?'var(--p)':'transparent')+';color:'+(_drillState.activeTab==='vulns'?'#fff':'var(--t)')+';cursor:pointer;font-size:.72rem">Vulnerabilidades ('+uniqVulns+')</button>'
      +'<button id="drillTabHosts" onclick="window._towersDrillTab(\'hosts\')" class="lb '+(_drillState.activeTab==='hosts'?'active':'')+'" style="padding:6px 14px;border:none;background:'+(_drillState.activeTab==='hosts'?'var(--p)':'transparent')+';color:'+(_drillState.activeTab==='hosts'?'#fff':'var(--t)')+';cursor:pointer;font-size:.72rem">Máquinas ('+hostCount+')</button>'
      +'</div>'
      +'<div style="display:inline-flex;align-items:center;gap:6px;flex:1;min-width:200px;max-width:320px;padding:6px 10px;border:1px solid var(--ol);border-radius:14px;background:var(--s1)">'
      +'<span class="material-icons-round" style="font-size:16px;color:var(--t2)">search</span>'
      +'<input id="drillSearch" type="text" oninput="window._towersDrillSearch(this.value)" value="'+_drillState.search+'" placeholder="Buscar '+(_drillState.activeTab==='vulns'?'vulnerabilidad/CVE':'hostname')+'..." style="border:none;outline:none;background:none;font-family:var(--fb);font-size:.72rem;width:100%;color:var(--t)">'
      +'</div></div>'
      // Body
      +'<div id="towersDrillBody"></div>'
      +'</div>';
    area.innerHTML = html;
    // Handler de cerrar (no se puede llamar directo a _drillState por ser var privada)
    window._drillState_close = function(){ _drillState.torre = null; _drillState.search = ''; area.innerHTML=''; };
    _renderDrillBody();
    area.scrollIntoView({behavior:'smooth',block:'nearest'});
  }

  function _renderDrillBody(){
    var body = document.getElementById('towersDrillBody'); if(!body) return;
    var torre = _drillState.torre;
    var rows = window._raw.filter(function(r){return (r.torre||'Sin clasificar')===torre;});
    var search = _drillState.search;

    if(_drillState.activeTab === 'vulns'){
      var vc = {};
      rows.forEach(function(r){
        if(!r.vulnName) return;
        if(!vc[r.vulnName]) vc[r.vulnName] = { count: 0, hosts: new Set(), kev: false, cves: new Set() };
        vc[r.vulnName].count++;
        vc[r.vulnName].hosts.add(r.hostname);
        if(r.isKEV) vc[r.vulnName].kev = true;
        (r._parsedCves||[]).forEach(function(c){ vc[r.vulnName].cves.add(c); });
      });
      var list = Object.entries(vc);
      if(search) list = list.filter(function(e){ return e[0].toLowerCase().includes(search) || [...e[1].cves].join(' ').toLowerCase().includes(search); });
      list.sort(function(a,b){return b[1].count-a[1].count;});
      var top = list.slice(0, 100);

      var html = '<div style="display:grid;grid-template-columns:1fr 70px 70px 70px;gap:0;padding:6px 18px;background:var(--s2);font-size:.62rem;text-transform:uppercase;color:var(--t2);font-weight:500">'
        +'<div>Vulnerabilidad</div><div>Count</div><div>Hosts</div><div>KEV</div></div>';
      if(!list.length){ html += '<div style="padding:28px;text-align:center;color:var(--t2);font-size:.75rem">Sin resultados para "'+search+'"</div>'; }
      else top.forEach(function(t){
        var nm = t[0], d = t[1];
        html += '<div style="display:grid;grid-template-columns:1fr 70px 70px 70px;gap:0;padding:7px 18px;border-top:1px solid var(--olv);font-size:.74rem;align-items:center">'
          +'<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+nm.replace(/"/g,'&quot;')+'">'+nm+'</div>'
          +'<div>'+d.count+'</div>'
          +'<div>'+d.hosts.size+'</div>'
          +'<div>'+(d.kev?'<span style="color:var(--err);font-weight:700">SÍ</span>':'—')+'</div>'
          +'</div>';
      });
      if(top.length===100 && list.length>100) html += '<div style="padding:8px 18px;font-size:.68rem;color:var(--t2);text-align:center">Mostrando top 100 de '+list.length+' únicas.</div>';
      body.innerHTML = html;
    } else {
      // Hosts — agregar por hostname
      var hm = {};
      rows.forEach(function(r){
        if(!r.hostname) return;
        if(!hm[r.hostname]) hm[r.hostname] = { hostname:r.hostname, entorno:r.entorno||'', vulns:0, kevs:0, maxDias:0, estadoAD:r.estadoAD };
        hm[r.hostname].vulns++;
        if(r.isKEV) hm[r.hostname].kevs++;
        if(r.diasQualys > hm[r.hostname].maxDias) hm[r.hostname].maxDias = r.diasQualys;
      });
      var hlist = Object.values(hm);
      if(search) hlist = hlist.filter(function(h){ return (h.hostname+' '+h.entorno).toLowerCase().includes(search); });
      hlist.sort(function(a,b){ return b.vulns - a.vulns; });

      var html = '<div style="display:grid;grid-template-columns:1.3fr 1fr 70px 70px 70px 80px;gap:0;padding:6px 18px;background:var(--s2);font-size:.62rem;text-transform:uppercase;color:var(--t2);font-weight:500">'
        +'<div>Host</div><div>Entorno</div><div>Vulns</div><div>KEVs</div><div>Max días</div><div>Estado AD</div></div>';
      if(!hlist.length){ html += '<div style="padding:28px;text-align:center;color:var(--t2);font-size:.75rem">Sin resultados para "'+search+'"</div>'; }
      else hlist.slice(0,200).forEach(function(h){
        html += '<div class="clickable" onclick="if(window.openHostModal)window.openHostModal(\''+h.hostname.replace(/\'/g,"\\'")+'\')" style="display:grid;grid-template-columns:1.3fr 1fr 70px 70px 70px 80px;gap:0;padding:7px 18px;border-top:1px solid var(--olv);font-size:.74rem;align-items:center;cursor:pointer" onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'">'
          +'<div style="font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+h.hostname+'">'+h.hostname+'</div>'
          +'<div style="color:var(--t2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+(h.entorno||'—')+'</div>'
          +'<div style="font-weight:700">'+h.vulns+'</div>'
          +'<div style="color:'+(h.kevs>0?'var(--err)':'var(--t2)')+';font-weight:'+(h.kevs>0?'700':'400')+'">'+h.kevs+'</div>'
          +'<div style="color:'+(h.maxDias>15?'var(--warn)':'var(--t2)')+'">'+h.maxDias+'d</div>'
          +'<div style="font-size:.66rem;color:var(--t2)">'+(h.estadoAD||'—')+'</div>'
          +'</div>';
      });
      if(hlist.length>200) html += '<div style="padding:8px 18px;font-size:.68rem;color:var(--t2);text-align:center">Mostrando primeras 200 de '+hlist.length+' máquinas.</div>';
      body.innerHTML = html;
    }
  }

  // ── Exponer utilidades ──────────────────────────────────────────────────────
  window._towersClassifyRow = classifyRow;
  window._towersClassifyHostType = classifyHostType;
  window._TOWERS = TOWERS;
  window._TOWER_DEFAULT_RULES = DEFAULT_RULES;
})();
