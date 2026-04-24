// ASISTENTE DE REMEDIACIÓN — Cerebro: Gemini IA
// Gemini analiza el parque, decide categorías, prioriza y genera el plan
// El código local solo prepara contexto, filtra hosts y renderiza la respuesta
(function(){
  var SLA_TARGET = 0.05; // 5%

  function normSev(vpr){
    if(!vpr) return 'Low';
    var v = vpr.toLowerCase();
    if(v.indexOf('9.0')>=0 || v.indexOf('10')>=0) return 'Critical';
    if(v.indexOf('7.0')>=0 || v.indexOf('8.')>=0) return 'High';
    if(v.indexOf('4.')>=0 || v.indexOf('5.')>=0 || v.indexOf('6.')>=0) return 'Medium';
    return 'Low';
  }

  // ── Load historical comparison data from IndexedDB ──
  // Returns { prevHostnames:Set, prevHostVulns:Map<hostname,vulnCount>, persistentHostnames:Set, snapshotsAnalyzed:number }
  async function loadHistoricalContext(){
    var result = { prevHostnames: null, prevHostVulns: null, persistentHostnames: null, snapshotsAnalyzed: 0 };
    if(typeof VDB === 'undefined') return result;
    try {
      var snaps = await VDB.listSnapshots();
      if(!snaps || snaps.length < 2) return result;

      // Sort by date desc (most recent first)
      snaps.sort(function(a,b){ return new Date(b.date) - new Date(a.date); });
      // Skip index 0 (current/latest), look at previous ones
      var previousSnaps = snaps.slice(1, 4); // up to 3 previous
      result.snapshotsAnalyzed = previousSnaps.length;

      // Per-host appearance counter across previous snapshots
      var hostAppearances = {};
      var firstPrev = null;

      for(var i=0; i<previousSnaps.length; i++){
        var s = await VDB.loadSnapshot(previousSnaps[i].id);
        if(!s || !s.rows) continue;
        var hostsInThisSnap = {};
        s.rows.forEach(function(r){
          if(!r.hostname) return;
          hostsInThisSnap[r.hostname] = (hostsInThisSnap[r.hostname]||0) + 1;
        });
        Object.keys(hostsInThisSnap).forEach(function(h){
          hostAppearances[h] = (hostAppearances[h]||0) + 1;
        });
        if(i === 0){
          // Most recent previous snapshot — store separately for "new" comparison
          firstPrev = hostsInThisSnap;
        }
      }

      // Hosts that appeared in ALL analyzed snapshots = persistent
      var persistent = new Set();
      Object.keys(hostAppearances).forEach(function(h){
        if(hostAppearances[h] >= previousSnaps.length) persistent.add(h);
      });

      result.prevHostnames = firstPrev ? new Set(Object.keys(firstPrev)) : null;
      result.prevHostVulns = firstPrev ? firstPrev : null;
      result.persistentHostnames = persistent;
      return result;
    } catch(e){
      console.warn('[Agent] No se pudo cargar contexto histórico:', e);
      return result;
    }
  }

  // Build host profiles from raw data, enriched with historical comparison
  function buildHostProfiles(raw, historical){
    historical = historical || {};
    var profiles = {};
    raw.forEach(function(r){
      var hn = r.hostname; if(!hn) return;
      if(!profiles[hn]){
        profiles[hn] = {
          hostname: hn, entorno: r.entorno || 'Sin clasificar',
          estadoAD: r.estadoAD || 'SIN ESTADO',
          diasLogon: r.diasLogon || 0, diasQualys: r.diasQualys || 0,
          vulns: 0, kevs: 0, maxVPR: 'Low', vulnNames: new Set(),
          isNew: false, isPersistent: false, vulnDelta: 0
        };
      }
      var p = profiles[hn];
      p.vulns++;
      if(r.isKEV) p.kevs++;
      if((r.diasQualys||0) > p.diasQualys) p.diasQualys = r.diasQualys;
      if((r.diasLogon||0) > p.diasLogon) p.diasLogon = r.diasLogon;
      var sev = normSev(r.nivelVPR);
      var rank = {Critical:4, High:3, Medium:2, Low:1};
      if(rank[sev] > rank[p.maxVPR]) p.maxVPR = sev;
      if(r.vulnName) p.vulnNames.add(r.vulnName);
    });

    // Apply historical enrichment
    var prevSet = historical.prevHostnames;
    var prevVulnsMap = historical.prevHostVulns;
    var persistentSet = historical.persistentHostnames;
    Object.values(profiles).forEach(function(p){
      if(prevSet){
        p.isNew = !prevSet.has(p.hostname);
      }
      if(persistentSet){
        p.isPersistent = persistentSet.has(p.hostname);
      }
      if(prevVulnsMap){
        var prevCount = prevVulnsMap[p.hostname] || 0;
        p.vulnDelta = p.vulns - prevCount;
      }
    });

    return Object.values(profiles);
  }

  // Build histograms and aggregates
  function buildContext(profiles, totalDevices, raw){
    var byEnv = {}, byEstado = {}, bySev = {Critical:0,High:0,Medium:0,Low:0};
    var logonBuckets = {'0-7':0,'8-30':0,'31-90':0,'91-180':0,'180+':0};
    var qualysBuckets = {'0-7':0,'8-30':0,'31-60':0,'61-90':0,'90+':0};
    var disabledWithVulns = 0, abandoned = 0, criticalActive = 0, ghosts = 0;
    var kevTotal = 0;

    profiles.forEach(function(p){
      // By env
      var e = p.entorno || 'Sin clasificar';
      if(!byEnv[e]) byEnv[e] = {hosts:0, vulns:0, kevs:0, critical:0, disabled:0};
      byEnv[e].hosts++;
      byEnv[e].vulns += p.vulns;
      byEnv[e].kevs += p.kevs;
      if(p.maxVPR==='Critical') byEnv[e].critical++;
      if(p.estadoAD==='DESHABILITADO') byEnv[e].disabled++;

      // By estado AD
      byEstado[p.estadoAD] = (byEstado[p.estadoAD]||0) + 1;

      // By max severity
      bySev[p.maxVPR] = (bySev[p.maxVPR]||0) + 1;

      // Logon histogram
      var dl = p.diasLogon;
      if(dl <= 7) logonBuckets['0-7']++;
      else if(dl <= 30) logonBuckets['8-30']++;
      else if(dl <= 90) logonBuckets['31-90']++;
      else if(dl <= 180) logonBuckets['91-180']++;
      else logonBuckets['180+']++;

      // Qualys histogram
      var dq = p.diasQualys;
      if(dq <= 7) qualysBuckets['0-7']++;
      else if(dq <= 30) qualysBuckets['8-30']++;
      else if(dq <= 60) qualysBuckets['31-60']++;
      else if(dq <= 90) qualysBuckets['61-90']++;
      else qualysBuckets['90+']++;

      // Key counts
      if(p.estadoAD==='DESHABILITADO' && p.vulns > 0) disabledWithVulns++;
      if(p.estadoAD==='HABILITADO' && p.diasLogon > 90) abandoned++;
      if(p.estadoAD==='HABILITADO' && (p.kevs > 0 || p.maxVPR==='Critical') && p.diasLogon <= 30) criticalActive++;
      if(p.estadoAD==='DESHABILITADO') ghosts++;
      kevTotal += p.kevs;
    });

    // Top 10 vulns by host count
    var vulnHosts = {};
    raw.forEach(function(r){
      if(!r.vulnName) return;
      if(!vulnHosts[r.vulnName]) vulnHosts[r.vulnName] = {hosts:new Set(), kev:r.isKEV||false, sev:normSev(r.nivelVPR)};
      vulnHosts[r.vulnName].hosts.add(r.hostname);
    });
    var topVulns = Object.entries(vulnHosts)
      .map(function(e){ return {name:e[0].substring(0,80), hosts:e[1].hosts.size, kev:e[1].kev, sev:e[1].sev}; })
      .sort(function(a,b){ return b.hosts - a.hosts; })
      .slice(0, 10);

    // Sample 12 representative hosts (3 from each profile type)
    var samples = [];
    function sample(filter, max){
      profiles.filter(filter).slice(0, max).forEach(function(p){
        samples.push({hostname:p.hostname, entorno:p.entorno, estadoAD:p.estadoAD, diasLogon:p.diasLogon, diasQualys:p.diasQualys, vulns:p.vulns, kevs:p.kevs, maxVPR:p.maxVPR});
      });
    }
    sample(function(p){ return p.estadoAD==='DESHABILITADO' && p.vulns > 0; }, 3);
    sample(function(p){ return p.estadoAD==='HABILITADO' && p.diasLogon > 90; }, 3);
    sample(function(p){ return p.estadoAD==='HABILITADO' && (p.kevs > 0 || p.maxVPR==='Critical'); }, 3);
    sample(function(p){ return p.estadoAD==='HABILITADO' && p.diasLogon <= 30 && p.maxVPR !== 'Critical'; }, 3);

    var totalVulnHosts = profiles.length;
    var currentPct = totalDevices > 0 ? (totalVulnHosts/totalDevices*100) : 0;
    var targetCount = Math.floor(totalDevices * SLA_TARGET);

    // Historical / temporal aggregates from enriched profiles
    var newHosts = profiles.filter(function(p){ return p.isNew; });
    var persistentHosts = profiles.filter(function(p){ return p.isPersistent; });
    var increasing = profiles.filter(function(p){ return p.vulnDelta > 0; });
    var decreasing = profiles.filter(function(p){ return p.vulnDelta < 0; });
    var hasHistory = profiles.some(function(p){ return p.isNew || p.isPersistent || p.vulnDelta !== 0; });

    var ctx = {
      sla: {
        contextoCajamar: 'El SLA se mide por % de DISPOSITIVOS vulnerables sobre el parque total, no por número de vulnerabilidades. Objetivo: < 5%.',
        objetivoMaximo: '5%',
        actualPct: parseFloat(currentPct.toFixed(2)),
        totalDispositivosParque: totalDevices,
        dispositivosVulnerables: totalVulnHosts,
        dispositivosObjetivoMax: targetCount,
        gapACerrar: Math.max(totalVulnHosts - targetCount, 0),
        slaCumplido: currentPct < 5
      },
      desglose: {
        porEntorno: byEnv,
        porEstadoAD: byEstado,
        porSeveridadMaxima: bySev,
        kevTotalInstancias: kevTotal
      },
      histogramas: {
        diasSinLogonUsuario: logonBuckets,
        diasUltimoEscaneoQualys: qualysBuckets
      },
      contadoresEspeciales: {
        deshabilitadosConVulns_FANTASMAS: disabledWithVulns,
        habilitadosSinLogon90d_ABANDONADOS: abandoned,
        habilitadosCriticosConUsuarioActivo: criticalActive
      },
      top10Vulnerabilidades: topVulns,
      muestraDispositivos: samples
    };

    if(hasHistory){
      ctx.tendenciaTemporal = {
        snapshotsAnalizados: 'Comparado con escaneos anteriores',
        dispositivosNuevos_NOAparecianAntes: newHosts.length,
        dispositivosPersistentes_VarianSnapshots: persistentHosts.length,
        dispositivosConMasVulnsQueAntes: increasing.length,
        dispositivosConMenosVulnsQueAntes: decreasing.length,
        muestraDispositivosNuevos: newHosts.slice(0,5).map(function(p){ return {hostname:p.hostname, entorno:p.entorno, vulns:p.vulns, kevs:p.kevs, estadoAD:p.estadoAD}; }),
        muestraDispositivosPersistentes: persistentHosts.slice(0,5).map(function(p){ return {hostname:p.hostname, entorno:p.entorno, vulns:p.vulns, kevs:p.kevs}; })
      };
    }

    return ctx;
  }

  window.renderAgentPanel = async function(){
    var ct = document.getElementById('ct-agent'); if(!ct) return;
    var raw = window._raw;
    if(!raw || !raw.length){
      ct.innerHTML='<div style="text-align:center;padding:60px;color:var(--t2)"><span class="material-icons-round" style="font-size:48px;display:block;opacity:.3;margin-bottom:12px">psychology</span>Carga un CSV primero</div>';
      return;
    }

    // Load historical context (compare against previous snapshots in IndexedDB)
    var historical = await loadHistoricalContext();
    window._agentHistorical = historical;

    var totalDevices = window.totalDevices || 0;
    var profiles = buildHostProfiles(raw, historical);
    var totalVulnHosts = profiles.length;
    var currentPct = totalDevices > 0 ? (totalVulnHosts/totalDevices*100) : 0;
    var targetCount = Math.floor(totalDevices * SLA_TARGET);
    var gap = Math.max(totalVulnHosts - targetCount, 0);
    var slaOk = currentPct < (SLA_TARGET*100);
    var hasHistorical = !!historical.prevHostnames;

    // Save context for Gemini
    window._agentContext = buildContext(profiles, totalDevices, raw);
    window._agentProfiles = profiles;

    var html = '<div class="rem-panel" style="max-width:1440px">';

    // ═══ HEADER ═══
    html+='<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:24px">'
      +'<div style="display:flex;align-items:center;gap:14px">'
      +'<div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;box-shadow:0 4px 14px rgba(124,58,237,.3)"><span class="material-icons-round" style="font-size:28px;color:#fff">psychology</span></div>'
      +'<div><div style="font-family:var(--fd);font-size:1.2rem;font-weight:700;letter-spacing:-.3px;display:flex;align-items:center;gap:8px">Especialista en Vulnerabilidades<span style="background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-size:.55rem;padding:2px 8px;border-radius:10px;font-weight:700;letter-spacing:.5px">GEMINI IA</span>'
      +(hasHistorical ? '<span style="background:var(--okc);color:var(--ok);font-size:.55rem;padding:2px 8px;border-radius:10px;font-weight:700;letter-spacing:.5px;display:inline-flex;align-items:center;gap:3px"><span class="material-icons-round" style="font-size:11px">history</span>HISTÓRICO ACTIVO</span>' : '')
      +'</div>'
      +'<div style="font-size:.73rem;color:var(--t2);margin-top:3px">El asistente analiza tu parque, evalúa el riesgo y genera un plan de acción priorizado'
      +(hasHistorical ? ' · Comparando con escaneos anteriores' : '')
      +'</div></div>'
      +'</div>'
      +'<button onclick="window._geminiOpenKeyModal()" title="Configurar API Key" style="display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:22px;border:1.5px solid var(--ol);background:var(--s1);color:var(--t2);cursor:pointer;transition:all .2s;font-family:var(--fd);font-size:.72rem;font-weight:500" onmouseover="this.style.borderColor=\'#7c3aed\';this.style.color=\'#7c3aed\'" onmouseout="this.style.borderColor=\'var(--ol)\';this.style.color=\'var(--t2)\'"><span class="material-icons-round" style="font-size:14px">key</span>API Key</button>'
      +'</div>';

    // ═══ SLA STATUS PANEL ═══
    html+='<div style="background:linear-gradient(135deg,'+(slaOk?'rgba(26,122,50,.06)':'rgba(209,70,0,.06)')+',var(--s1));border:1px solid '+(slaOk?'rgba(26,122,50,.2)':'rgba(209,70,0,.2)')+';border-radius:var(--r);padding:22px;margin-bottom:20px;box-shadow:var(--e1)">';
    html+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:18px;align-items:center">';

    html+='<div><div style="font-size:.6rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">Estado Actual</div>'
      +'<div style="font-family:var(--fd);font-size:2.2rem;font-weight:700;color:'+(slaOk?'var(--ok)':'var(--err)')+';line-height:1;letter-spacing:-.5px">'+currentPct.toFixed(2)+'<span style="font-size:1rem">%</span></div>'
      +'<div style="font-size:.65rem;color:var(--t2);margin-top:4px">'+totalVulnHosts.toLocaleString()+' / '+totalDevices.toLocaleString()+' dispositivos</div></div>';

    html+='<div><div style="font-size:.6rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">Objetivo SLA Cajamar</div>'
      +'<div style="font-family:var(--fd);font-size:2.2rem;font-weight:700;color:var(--p);line-height:1;letter-spacing:-.5px">&lt;5<span style="font-size:1rem">%</span></div>'
      +'<div style="font-size:.65rem;color:var(--t2);margin-top:4px">máx '+targetCount.toLocaleString()+' dispositivos vulnerables</div></div>';

    html+='<div><div style="font-size:.6rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">Gap a Cerrar</div>'
      +'<div style="font-family:var(--fd);font-size:2.2rem;font-weight:700;color:'+(gap>0?'var(--err)':'var(--ok)')+';line-height:1;letter-spacing:-.5px">'+(gap>0?'-':'')+gap+'</div>'
      +'<div style="font-size:.65rem;color:var(--t2);margin-top:4px">'+(gap>0?'dispositivos para cumplir':'¡SLA cumplido!')+'</div></div>';

    html+='<div style="text-align:center">'
      +'<div style="display:inline-flex;align-items:center;gap:6px;padding:10px 20px;border-radius:24px;background:'+(slaOk?'var(--okc)':'var(--errc)')+';color:'+(slaOk?'var(--ok)':'var(--err)')+';font-family:var(--fd);font-weight:700;font-size:.85rem">'
      +'<span class="material-icons-round" style="font-size:18px">'+(slaOk?'check_circle':'error')+'</span>'
      +(slaOk?'SLA OK':'SLA EN RIESGO')
      +'</div></div>';

    html+='</div>';

    var pctOfMax = Math.min((currentPct/(SLA_TARGET*100*2))*100, 100);
    html+='<div style="margin-top:16px;position:relative"><div style="display:flex;justify-content:space-between;font-size:.62rem;color:var(--t2);margin-bottom:5px"><span>0%</span><span>5% (objetivo)</span><span>10%</span></div>'
      +'<div style="position:relative;height:10px;background:var(--s2);border-radius:5px;overflow:visible">'
      +'<div style="position:absolute;height:100%;width:'+pctOfMax+'%;background:linear-gradient(90deg,'+(slaOk?'var(--ok),var(--ok)':'var(--warn),var(--err)')+');border-radius:5px;transition:width .8s"></div>'
      +'<div style="position:absolute;left:50%;top:-3px;bottom:-3px;width:2px;background:var(--t);border-radius:1px"></div>'
      +'</div></div>';

    html+='</div>';

    // ═══ GENERATE PLAN BUTTON / GEMINI RESULT AREA ═══
    html+='<div id="agentPlanArea">'
      +'<div style="text-align:center;padding:50px 20px;background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);margin-bottom:20px;border:2px dashed rgba(124,58,237,.2)">'
      +'<div style="width:64px;height:64px;border-radius:18px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;margin:0 auto 16px;box-shadow:0 6px 20px rgba(124,58,237,.35)"><span class="material-icons-round" style="font-size:32px;color:#fff">auto_awesome</span></div>'
      +'<div style="font-family:var(--fd);font-size:1.1rem;font-weight:700;margin-bottom:6px">Pide al especialista IA que analice tu parque</div>'
      +'<div style="font-size:.78rem;color:var(--t2);margin-bottom:20px;max-width:560px;margin-left:auto;margin-right:auto;line-height:1.55">Gemini evaluará el estado de los <strong>'+totalVulnHosts.toLocaleString()+' dispositivos vulnerables</strong>, identificará patrones, propondrá categorías de acción y generará un plan priorizado para cumplir el SLA del 5% de Cajamar.</div>'
      +'<button onclick="window._agentGeminiPlan()" style="display:inline-flex;align-items:center;gap:10px;padding:14px 32px;border-radius:30px;border:none;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-family:var(--fd);font-size:.92rem;font-weight:600;cursor:pointer;box-shadow:0 4px 18px rgba(124,58,237,.35);transition:all .25s" onmouseover="this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'0 6px 24px rgba(124,58,237,.45)\'" onmouseout="this.style.transform=\'none\';this.style.boxShadow=\'0 4px 18px rgba(124,58,237,.35)\'">'
      +'<span class="material-icons-round" style="font-size:22px">auto_awesome</span>Generar Plan con IA</button>'
      +'<div style="margin-top:14px;font-size:.65rem;color:var(--t2)">Modelo: '+(window._geminiActiveModel||'gemini-3-flash-preview')+' · Tu API key se guarda solo en tu navegador</div>'
      +'</div>'
      +'</div>';

    html+='</div>';
    ct.innerHTML = html;
  };

  // ── GEMINI PLAN GENERATION ──
  // Two-phase streaming:
  //   PHASE 1: stream markdown narrative (diagnosis, quick wins, recommendation) → progressive render
  //   PHASE 2: stream JSON with categories (filter criteria + actions) → structured render
  window._agentGeminiPlan = async function(){
    if(!window._geminiHasKey || !window._geminiHasKey()){
      window._geminiOpenKeyModal(function(){ window._agentGeminiPlan(); });
      return;
    }
    var area = document.getElementById('agentPlanArea'); if(!area) return;

    // Inject blink keyframe if not present
    if(!document.getElementById('streamBlinkStyle')){
      var style = document.createElement('style');
      style.id = 'streamBlinkStyle';
      style.textContent = '@keyframes streamBlink{0%,49%{opacity:1}50%,100%{opacity:0}}.md-cursor{display:inline-block;width:8px;height:1.1em;background:#7c3aed;vertical-align:-2px;margin-left:2px;animation:streamBlink 1s steps(1) infinite;border-radius:2px}';
      document.head.appendChild(style);
    }

    // Layout: card with header (status) + body (live markdown) + placeholder for phase 2
    area.innerHTML = '<div id="agentPhase1Card" style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);margin-bottom:18px;overflow:hidden;border-left:4px solid #7c3aed">'
      +'<div style="padding:18px 24px;border-bottom:1px solid var(--olv);display:flex;align-items:center;gap:14px">'
      +'<div style="width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;flex-shrink:0;box-shadow:0 4px 14px rgba(124,58,237,.3)"><span class="material-icons-round" style="font-size:22px;color:#fff;animation:spin 1.5s linear infinite" id="agentPhaseIcon">auto_awesome</span></div>'
      +'<div style="flex:1"><div style="font-family:var(--fd);font-weight:700;font-size:1rem">Especialista IA — Análisis del Parque</div><div id="agentStreamStatus" style="font-size:.7rem;color:var(--t2);margin-top:3px">Iniciando conexión con Gemini...</div></div>'
      +'<div id="agentStreamCounter" style="font-family:Monaco,monospace;font-size:.65rem;color:var(--t2);background:var(--s2);padding:4px 10px;border-radius:10px">0 tokens</div>'
      +'</div>'
      +'<div id="agentMdContainer" style="padding:22px 28px;font-size:.85rem;color:var(--t);min-height:120px"></div>'
      +'</div>'
      +'<div id="agentPhase2Slot"></div>';

    var ctx = window._agentContext;

    // ════════════════════════════════════════
    // PHASE 1: Stream markdown narrative
    // ════════════════════════════════════════
    var systemPrompt1 = 'Eres un experto sénior en gestión de vulnerabilidades en DXC Technology dando servicio al banco Cajamar. '
      +'CONTEXTO CRÍTICO: Cajamar mide el SLA por % de DISPOSITIVOS vulnerables sobre el parque total (NO por número de vulnerabilidades). Objetivo: < 5%. '
      +'Eliminar un dispositivo del recuento (decomisar, deshabilitar, sacar de la red) tiene el MISMO efecto que parchearlo. '
      +'Las acciones de "limpieza" suelen ser MÁS RENTABLES que parchear.\n\n'
      +'Responde SIEMPRE en español, en formato MARKDOWN limpio. Tono ejecutivo, accionable, específico con números. NO uses tablas markdown (usa listas). '
      +'Razona como un consultor sénior, no como un teórico.';

    var hasHist = !!(ctx && ctx.tendenciaTemporal);
    var userPrompt1 = 'Analiza el estado del parque vulnerable de Cajamar y genera un INFORME EJECUTIVO en MARKDOWN con esta estructura exacta:\n\n'
      +'## Diagnóstico\n'
      +'(2-3 frases describiendo la situación actual del SLA y la salud general del parque'
      +(hasHist ? '. Menciona explícitamente la evolución temporal: cuántos dispositivos nuevos han aparecido, cuántos persisten desde escaneos anteriores' : '')
      +')\n\n'
      +'## Plan de Ataque Priorizado\n'
      +'(Lista numerada con las 4-5 acciones más impactantes ordenadas por prioridad. Cada acción debe incluir: número estimado de dispositivos que afecta, impacto en el SLA en puntos porcentuales, y esfuerzo)\n\n'
      +'## Quick Wins\n'
      +'(Lista con 3 acciones de bajo esfuerzo y alto impacto que se pueden hacer YA — tipicamente limpieza de fantasmas y abandonados)\n\n'
      +(hasHist ? '## Equipos Recién Aparecidos\n'
        +'(Si hay dispositivos nuevos en este escaneo que no estaban en el anterior, comenta de dónde podrían venir y qué hacer con ellos. Si no hay, omite esta sección.)\n\n' : '')
      +'## Riesgos a Vigilar\n'
      +'(2-3 cosas que pueden empeorar el SLA en próximas semanas si no se actúa)\n\n'
      +'## Recomendación Inmediata\n'
      +'(UNA frase clara: qué empezar HOY como primera acción concreta)\n\n'
      +'DATOS DEL PARQUE:\n```json\n'+JSON.stringify(ctx, null, 2)+'\n```';

    var mdContainer = document.getElementById('agentMdContainer');
    var statusEl = document.getElementById('agentStreamStatus');
    var counterEl = document.getElementById('agentStreamCounter');

    function setStatus(text){ if(statusEl) statusEl.textContent = text; }

    var phase1Markdown = '';

    window._geminiAskStream(userPrompt1, systemPrompt1, {
      temperature: 0.4,
      maxOutputTokens: 4096
    }, {
      onChunk: function(chunkText, fullText){
        phase1Markdown = fullText;
        if(mdContainer){
          // Render full markdown progressively + append cursor
          mdContainer.innerHTML = mdToHtml(fullText) + '<span class="md-cursor"></span>';
        }
        if(counterEl) counterEl.textContent = Math.round(fullText.length/4).toLocaleString()+' tok';

        // Status updates based on visible markdown sections
        if(fullText.indexOf('Recomendación Inmediata') >= 0) setStatus('Finalizando recomendación inmediata...');
        else if(fullText.indexOf('Riesgos') >= 0) setStatus('Identificando riesgos a vigilar...');
        else if(fullText.indexOf('Quick Wins') >= 0) setStatus('Calculando quick wins...');
        else if(fullText.indexOf('Plan de Ataque') >= 0) setStatus('Generando plan de ataque priorizado...');
        else if(fullText.indexOf('Diagnóstico') >= 0) setStatus('Escribiendo diagnóstico ejecutivo...');
        else if(fullText.length > 0) setStatus('Gemini está pensando...');
      },
      onDone: function(fullText){
        phase1Markdown = fullText;
        if(mdContainer) mdContainer.innerHTML = mdToHtml(fullText); // remove cursor
        var icon = document.getElementById('agentPhaseIcon');
        if(icon){ icon.style.animation = 'none'; icon.textContent = 'auto_awesome'; }
        setStatus('Análisis ejecutivo completo · Generando categorías estructuradas...');
        // Trigger phase 2
        runPhase2(area);
      },
      onError: function(e){
        var errMsg = e.message || 'Error desconocido';
        if(errMsg === 'NO_KEY'){
          window._geminiOpenKeyModal(function(){ window._agentGeminiPlan(); });
          return;
        }
        showStreamError(area, errMsg);
      }
    });
  };

  // ════════════════════════════════════════
  // PHASE 2: Stream structured JSON (categories with criteria)
  // ════════════════════════════════════════
  function runPhase2(area){
    var ctx = window._agentContext;
    var slot = document.getElementById('agentPhase2Slot');
    if(!slot) return;

    // Phase 2 placeholder card
    slot.innerHTML = '<div id="agentPhase2Card" style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:18px 24px;margin-bottom:18px;display:flex;align-items:center;gap:14px">'
      +'<div style="width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;flex-shrink:0"><span class="material-icons-round" style="color:#fff;font-size:20px;animation:spin 1.5s linear infinite">autorenew</span></div>'
      +'<div style="flex:1"><div style="font-family:var(--fd);font-weight:700;font-size:.9rem">Generando categorías de acción</div><div id="agentP2Status" style="font-size:.68rem;color:var(--t2);margin-top:3px">Identificando criterios de filtrado de hosts...</div></div>'
      +'<div id="agentP2Counter" style="font-family:Monaco,monospace;font-size:.65rem;color:var(--t2);background:var(--s2);padding:4px 10px;border-radius:10px">0 tok</div>'
      +'</div>';

    var hasHist = !!(ctx && ctx.tendenciaTemporal);
    var systemPrompt2 = 'Eres un experto en gestión de vulnerabilidades. Devuelve un JSON estricto con categorías de hosts a remediar, según el schema. '
      +'IMPORTANTE: define criterios precisos que se puedan aplicar como filtros sobre los datos. '
      +'Recuerda: Cajamar mide SLA por dispositivos vulnerables (<5%). Limpiar fantasmas y abandonados es más rentable que parchear.\n\n'
      +'CAMPOS DISPONIBLES PARA CRITERIOS:\n'
      +'- estadoAD: HABILITADO / DESHABILITADO / SIN ESTADO\n'
      +'- minDiasLogon, maxDiasLogon: días sin que el usuario haga logon\n'
      +'- minDiasQualys, maxDiasQualys: días desde el último escaneo\n'
      +'- soloKEV: hosts con vulnerabilidades CISA KEV\n'
      +'- severidadMin: Low/Medium/High/Critical\n'
      +(hasHist ? '- soloNuevos: hosts que NO existían en el escaneo anterior (RECIÉN APARECIDOS — categoría muy importante para investigar de dónde vienen)\n'
        +'- soloPersistentes: hosts vulnerables en TODOS los escaneos previos (REINCIDENTES, atascados)\n'
        +'- vulnDeltaMin / vulnDeltaMax: cambio en número de vulns respecto al escaneo anterior\n' : '')
      +'\nCREA AL MENOS UNA CATEGORÍA POR CADA PATRÓN DETECTABLE EN LOS DATOS. '
      +(hasHist ? 'Si hay hosts nuevos significativos, crea una categoría "Recién Aparecidos". Si hay persistentes, crea una categoría "Reincidentes". ' : '')
      +'Mezcla criterios cuando sea útil (ej: estadoAD=HABILITADO + soloKEV + minDiasLogon=30).';

    var userPrompt2 = 'Devuelve un JSON con las categorías priorizadas según el schema. '
      +'Mínimo 4 categorías, máximo 8. Ordénalas por prioridad (1 = más urgente). '
      +'Las categorías que LIMPIAN dispositivos del recuento (fantasmas, abandonados, recién aparecidos sospechosos) suelen tener mayor impacto en el SLA que parchear.\n\n'
      +'DATOS:\n'+JSON.stringify(ctx);

    var responseSchema = {
      type: 'object',
      properties: {
        estadoSLA: { type: 'string', enum: ['OK', 'EN_RIESGO', 'CRITICO'] },
        categorias: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              nombre: { type: 'string' },
              icono: { type: 'string', description: 'Material icon name (visibility_off, person_off, local_fire_department, sync_problem, schedule, help_outline, check_circle)' },
              color: { type: 'string', enum: ['red', 'orange', 'purple', 'blue', 'green', 'cyan'] },
              prioridad: { type: 'integer' },
              esfuerzo: { type: 'string', enum: ['low', 'medium', 'high'] },
              impactoSLA: { type: 'string', enum: ['low', 'medium', 'high'] },
              criterios: {
                type: 'object',
                description: 'Filtros aplicables sobre cada host. Combina los que necesites.',
                properties: {
                  estadoAD: { type: 'array', items: { type: 'string', enum: ['HABILITADO', 'DESHABILITADO', 'SIN ESTADO'] } },
                  minDiasLogon: { type: 'integer' },
                  maxDiasLogon: { type: 'integer' },
                  minDiasQualys: { type: 'integer' },
                  maxDiasQualys: { type: 'integer' },
                  soloKEV: { type: 'boolean' },
                  severidadMin: { type: 'string', enum: ['Low', 'Medium', 'High', 'Critical'] },
                  soloNuevos: { type: 'boolean', description: 'Hosts que NO aparecían en el escaneo anterior (recién aparecidos)' },
                  soloPersistentes: { type: 'boolean', description: 'Hosts vulnerables en TODOS los escaneos analizados' },
                  vulnDeltaMin: { type: 'integer', description: 'Mínimo aumento de vulns vs escaneo anterior (usar números positivos)' },
                  vulnDeltaMax: { type: 'integer', description: 'Máximo aumento de vulns vs escaneo anterior (negativo = mejora)' }
                }
              },
              accion: { type: 'string' },
              razon: { type: 'string' },
              estimacionHosts: { type: 'integer' }
            },
            required: ['id', 'nombre', 'icono', 'color', 'prioridad', 'esfuerzo', 'impactoSLA', 'criterios', 'accion', 'razon']
          }
        }
      },
      required: ['estadoSLA', 'categorias']
    };

    window._geminiAskStream(userPrompt2, systemPrompt2, {
      responseSchema: responseSchema,
      temperature: 0.3,
      maxOutputTokens: 4096
    }, {
      onChunk: function(chunkText, fullText){
        var c = document.getElementById('agentP2Counter');
        if(c) c.textContent = Math.round(fullText.length/4).toLocaleString()+' tok';
        // Count opened categorias as a progress indicator
        var matches = fullText.match(/"id"\s*:/g);
        var s = document.getElementById('agentP2Status');
        if(s && matches) s.textContent = matches.length+' categoría'+(matches.length>1?'s':'')+' identificadas...';
      },
      onDone: function(fullText){
        var plan;
        try { plan = JSON.parse(fullText); }
        catch(e){
          var slot = document.getElementById('agentPhase2Slot');
          if(slot) slot.innerHTML = '<div style="background:var(--errc);color:var(--err);padding:14px 18px;border-radius:12px;font-size:.78rem;margin-bottom:18px">No se pudieron generar las categorías estructuradas. <button onclick="window._agentGeminiPlan()" style="margin-left:8px;padding:4px 12px;border-radius:12px;border:1.5px solid var(--err);background:transparent;color:var(--err);font-family:var(--fd);font-size:.7rem;cursor:pointer">Reintentar</button></div>';
          // Update status of phase 1 to show it's done
          var s = document.getElementById('agentStreamStatus');
          if(s) s.textContent = 'Análisis ejecutivo completo';
          return;
        }
        window._agentPlan = plan;
        renderCategoriesPhase(plan);
      },
      onError: function(e){
        var slot = document.getElementById('agentPhase2Slot');
        if(slot) slot.innerHTML = '<div style="background:var(--errc);color:var(--err);padding:14px 18px;border-radius:12px;font-size:.78rem;margin-bottom:18px">Error al generar categorías: '+escapeHtml(e.message||'')+' <button onclick="window._agentGeminiPlan()" style="margin-left:8px;padding:4px 12px;border-radius:12px;border:1.5px solid var(--err);background:transparent;color:var(--err);font-family:var(--fd);font-size:.7rem;cursor:pointer">Reintentar</button></div>';
      }
    });
  }

  // Render only the categories portion (after phase 1 markdown is already shown)
  function renderCategoriesPhase(plan){
    var slot = document.getElementById('agentPhase2Slot');
    if(!slot) return;
    var profiles = window._agentProfiles || [];

    // Update phase 1 status
    var s = document.getElementById('agentStreamStatus');
    if(s) s.textContent = 'Análisis completo · ' + (plan.categorias||[]).length + ' categorías de acción identificadas';

    var html = '';

    // Category section header
    html += '<div style="font-family:var(--fd);font-size:.88rem;font-weight:600;color:var(--t2);margin:8px 0 12px;display:flex;align-items:center;gap:8px;text-transform:uppercase;letter-spacing:.5px">'
      +'<span class="material-icons-round" style="font-size:18px;color:#7c3aed">format_list_numbered</span>'
      +'Categorías de Acción · Hosts Filtrables'
      +'<span style="background:#7c3aed;color:#fff;font-size:.6rem;padding:2px 8px;border-radius:10px;margin-left:4px;font-weight:700">'+(plan.categorias||[]).length+'</span>'
      +'<span style="flex:1;height:1px;background:linear-gradient(90deg,var(--olv),transparent);margin-left:8px"></span>'
      +'</div>';

    var sortedCats = (plan.categorias||[]).slice().sort(function(a,b){ return (a.prioridad||99) - (b.prioridad||99); });

    // ═══ SLA SIMULATOR ═══
    var ctx = window._agentContext;
    var slaCurrentPct = ctx ? ctx.sla.actualPct : 0;
    var slaTotal = ctx ? ctx.sla.totalDispositivosParque : 0;
    var slaVulns = ctx ? ctx.sla.dispositivosVulnerables : 0;
    var slaOk = slaCurrentPct < 5;

    html += '<div style="background:linear-gradient(135deg,rgba(124,58,237,.06),var(--s1));border:1px solid rgba(124,58,237,.25);border-radius:var(--r);padding:18px 22px;margin-bottom:18px;box-shadow:var(--e1)">'
      +'<div style="font-family:var(--fd);font-size:.85rem;font-weight:600;margin-bottom:6px;display:flex;align-items:center;gap:8px">'
      +'<span class="material-icons-round" style="font-size:18px;color:#7c3aed">science</span>Simulador SLA · Marca categorías para proyectar el resultado'
      +'</div>'
      +'<div style="font-size:.68rem;color:var(--t2);margin-bottom:14px">Por defecto se preseleccionan las categorías de bajo esfuerzo y alto impacto</div>';

    // Checkbox pills
    html += '<div id="agentSimulator" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px">';
    sortedCats.forEach(function(cat, i){
      var meta = COLOR_MAP[cat.color] || COLOR_MAP.blue;
      var actualHosts = filterHostsByCriteria(profiles, cat.criterios);
      var realCount = actualHosts.length;
      // Auto-select quick wins: low effort + high impact
      var autoCheck = (cat.esfuerzo === 'low' && cat.impactoSLA === 'high') ? 'checked' : '';
      html += '<label style="display:inline-flex;align-items:center;gap:7px;padding:7px 13px;border-radius:20px;background:var(--s1);border:1.5px solid var(--olv);cursor:pointer;font-size:.72rem;font-weight:500;transition:all .2s" onmouseover="this.style.borderColor=\''+meta.border+'\'" onmouseout="this.style.borderColor=\'var(--olv)\'">'
        +'<input type="checkbox" data-count="'+realCount+'" '+autoCheck+' onchange="window._agentSimCalc()" style="accent-color:#7c3aed;width:14px;height:14px">'
        +'<span class="material-icons-round" style="font-size:14px;color:'+meta.color+'">'+escapeAttr(cat.icono||'label')+'</span>'
        +escapeHtml(cat.nombre||'')+' <strong style="color:'+meta.color+'">('+realCount+')</strong>'
        +'</label>';
    });
    html += '</div>';

    // Result display
    html += '<div id="agentSimResult" style="background:var(--s2);border-radius:12px;padding:14px 18px;display:flex;align-items:center;gap:18px;flex-wrap:wrap">'
      +'<div style="text-align:center"><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase;letter-spacing:.4px;font-weight:600">Actual</div><div id="agSimFrom" style="font-family:var(--fd);font-weight:700;font-size:1.4rem;color:'+(slaOk?'var(--ok)':'var(--err)')+';line-height:1;letter-spacing:-.3px">'+slaCurrentPct.toFixed(2)+'%</div><div style="font-size:.55rem;color:var(--t2);margin-top:2px">'+slaVulns+' hosts</div></div>'
      +'<span class="material-icons-round" style="font-size:24px;color:var(--t2)">arrow_forward</span>'
      +'<div style="text-align:center"><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase;letter-spacing:.4px;font-weight:600">Tras Acciones</div><div id="agSimTo" style="font-family:var(--fd);font-weight:700;font-size:1.4rem;line-height:1;letter-spacing:-.3px">--</div><div id="agSimToHosts" style="font-size:.55rem;color:var(--t2);margin-top:2px">--</div></div>'
      +'<div style="flex:1;min-width:180px;border-left:1px solid var(--olv);padding-left:18px"><div id="agSimMsg" style="font-size:.78rem;color:var(--t2);line-height:1.5">Marca categorías arriba para simular el impacto en el SLA</div></div>'
      +'<div id="agSimBadge"></div>'
      +'</div>'
      +'</div>';

    sortedCats.forEach(function(cat, idx){
      var meta = COLOR_MAP[cat.color] || COLOR_MAP.blue;
      var actualHosts = filterHostsByCriteria(profiles, cat.criterios);
      var realCount = actualHosts.length;
      var effortIcon = cat.esfuerzo==='low'?'🟢':cat.esfuerzo==='medium'?'🟡':'🔴';
      var impactIcon = cat.impactoSLA==='high'?'⭐⭐⭐':cat.impactoSLA==='medium'?'⭐⭐':'⭐';

      html += '<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);margin-bottom:12px;overflow:hidden;border-left:4px solid '+meta.border+';transition:all .25s" onmouseover="this.style.boxShadow=\'var(--e2)\'" onmouseout="this.style.boxShadow=\'var(--e1)\'">';
      html += '<div style="padding:16px 20px;cursor:pointer;display:flex;align-items:center;gap:14px" onclick="window._agentToggleCat('+idx+')">';
      html += '<div style="display:flex;align-items:center;gap:10px;flex-shrink:0">'
        +'<div style="width:32px;height:32px;border-radius:50%;background:'+meta.color+';color:#fff;display:grid;place-items:center;font-family:var(--fd);font-weight:700;font-size:.85rem">'+(cat.prioridad||idx+1)+'</div>'
        +'<div style="width:42px;height:42px;border-radius:11px;background:'+meta.bg+';display:grid;place-items:center"><span class="material-icons-round" style="font-size:22px;color:'+meta.color+'">'+escapeAttr(cat.icono||'label')+'</span></div>'
        +'</div>';
      html += '<div style="flex:1;min-width:0">'
        +'<div style="font-family:var(--fd);font-size:1rem;font-weight:600;margin-bottom:3px">'+escapeHtml(cat.nombre||'')+'</div>'
        +'<div style="font-size:.72rem;color:var(--t2);display:flex;gap:14px;flex-wrap:wrap">'
        +'<span><strong style="color:var(--t)">'+realCount+'</strong> dispositivos reales</span>'
        +(cat.estimacionHosts && cat.estimacionHosts !== realCount ? '<span style="color:var(--t2)">(IA estimó '+cat.estimacionHosts+')</span>' : '')
        +'<span>Esfuerzo: '+effortIcon+' '+cat.esfuerzo+'</span>'
        +'<span>Impacto SLA: '+impactIcon+'</span>'
        +'</div></div>';
      html += '<div style="text-align:center;flex-shrink:0"><div style="font-family:var(--fd);font-weight:700;font-size:1.6rem;color:'+meta.color+';line-height:1;letter-spacing:-.3px">'+realCount+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">hosts</div></div>';
      html += '<span class="material-icons-round" id="agentChev-'+idx+'" style="font-size:22px;color:var(--t2);transition:transform .2s;flex-shrink:0">expand_more</span>';
      html += '</div>';

      var startOpen = idx === 0 ? 'block' : 'none';
      html += '<div id="agentBody-'+idx+'" style="display:'+startOpen+';border-top:1px solid var(--olv);padding:18px 20px;background:var(--s)">';
      html += '<div style="background:'+meta.bg+';border-left:3px solid '+meta.border+';padding:14px 18px;border-radius:0 8px 8px 0;margin-bottom:14px">'
        +'<div style="font-size:.6rem;text-transform:uppercase;letter-spacing:.5px;color:'+meta.color+';font-weight:700;margin-bottom:5px">Plan de Acción</div>'
        +'<div style="font-family:var(--fd);font-size:.92rem;font-weight:600;color:var(--t);margin-bottom:8px">'+escapeHtml(cat.accion||'')+'</div>'
        +'<div style="font-size:.75rem;color:var(--t2);line-height:1.6">'+escapeHtml(cat.razon||'')+'</div>'
        +'</div>';

      var critPills = [];
      var c = cat.criterios || {};
      if(c.estadoAD && c.estadoAD.length > 0) critPills.push('Estado: '+c.estadoAD.join('/'));
      if(c.minDiasLogon != null) critPills.push('Logon ≥'+c.minDiasLogon+'d');
      if(c.maxDiasLogon != null) critPills.push('Logon ≤'+c.maxDiasLogon+'d');
      if(c.minDiasQualys != null) critPills.push('Qualys ≥'+c.minDiasQualys+'d');
      if(c.maxDiasQualys != null) critPills.push('Qualys ≤'+c.maxDiasQualys+'d');
      if(c.soloKEV) critPills.push('Solo KEV');
      if(c.severidadMin) critPills.push('Severidad ≥'+c.severidadMin);
      if(c.soloNuevos) critPills.push('🆕 Recién aparecidos');
      if(c.soloPersistentes) critPills.push('🔁 Persistentes');
      if(c.vulnDeltaMin != null && c.vulnDeltaMin > 0) critPills.push('+'+c.vulnDeltaMin+' vulns vs anterior');
      if(c.vulnDeltaMax != null && c.vulnDeltaMax < 0) critPills.push(c.vulnDeltaMax+' vulns vs anterior');
      if(critPills.length > 0){
        html += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px"><span style="font-size:.62rem;color:var(--t2);text-transform:uppercase;letter-spacing:.4px;font-weight:600;align-self:center;margin-right:4px">Filtro:</span>';
        critPills.forEach(function(p){
          html += '<span style="padding:3px 10px;background:var(--s2);border-radius:14px;font-size:.66rem;color:var(--t2);font-family:var(--fd)">'+escapeHtml(p)+'</span>';
        });
        html += '</div>';
      }

      if(realCount > 0){
        var sampleHosts = actualHosts.slice(0, 10);
        html += '<div style="font-size:.65rem;color:var(--t2);font-weight:600;text-transform:uppercase;letter-spacing:.3px;margin-bottom:8px">Dispositivos en esta categoría ('+Math.min(10,realCount)+' de '+realCount+')</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px">';
        sampleHosts.forEach(function(h){
          html += '<div style="background:var(--s1);border:1px solid var(--olv);border-radius:8px;padding:8px 12px;font-size:.7rem">'
            +'<div style="display:flex;justify-content:space-between;align-items:center;gap:6px;margin-bottom:3px">'
            +'<span style="font-family:var(--fd);font-weight:600;font-size:.74rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(h.hostname)+'</span>'
            +(h.kevs>0?'<span style="background:#dc2626;color:#fff;padding:1px 6px;border-radius:8px;font-size:.55rem;font-weight:700">KEV</span>':'')
            +'</div>'
            +'<div style="display:flex;gap:6px;color:var(--t2);font-size:.62rem;flex-wrap:wrap">'
            +'<span>'+escapeHtml(h.entorno)+'</span><span>·</span>'
            +'<span>'+h.vulns+' vulns</span><span>·</span>'
            +'<span>Q: '+h.diasQualys+'d</span><span>·</span>'
            +'<span>AD: '+h.diasLogon+'d</span>'
            +'</div></div>';
        });
        html += '</div>';
        if(realCount > 10){
          html += '<div style="text-align:center;margin-top:10px;font-size:.7rem;color:var(--t2)">... y '+(realCount-10)+' dispositivos más</div>';
        }
        html += '<div style="margin-top:14px"><button onclick="window._agentExportCatGemini('+idx+')" style="display:inline-flex;align-items:center;gap:5px;padding:7px 16px;border-radius:18px;border:1.5px solid '+meta.border+';background:transparent;color:'+meta.color+';font-family:var(--fd);font-size:.72rem;font-weight:500;cursor:pointer;transition:all .2s"><span class="material-icons-round" style="font-size:14px">download</span>Exportar lista CSV</button></div>';
      } else {
        html += '<div style="text-align:center;padding:20px;color:var(--t2);font-size:.78rem;background:var(--s2);border-radius:8px"><span class="material-icons-round" style="font-size:20px;display:block;margin-bottom:6px;opacity:.4">inbox</span>Ningún dispositivo cumple los criterios de esta categoría en tu parque actual</div>';
      }

      html += '</div></div>';
    });

    // Regenerate button at the bottom
    html += '<div style="text-align:center;margin-top:20px"><button onclick="window._agentGeminiPlan()" style="display:inline-flex;align-items:center;gap:6px;padding:9px 22px;border-radius:22px;border:1.5px solid #7c3aed;background:transparent;color:#7c3aed;font-family:var(--fd);font-size:.78rem;font-weight:500;cursor:pointer;transition:all .2s" onmouseover="this.style.background=\'rgba(124,58,237,.08)\'" onmouseout="this.style.background=\'transparent\'"><span class="material-icons-round" style="font-size:15px">refresh</span>Regenerar análisis IA</button></div>';

    slot.innerHTML = html;

    // Trigger initial simulator calculation (auto-selected quick wins)
    setTimeout(function(){ if(window._agentSimCalc) window._agentSimCalc(); }, 50);
  }

  function showStreamError(area, errMsg){
    area.innerHTML = '<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:24px;margin-bottom:20px;border-left:4px solid var(--err)">'
      +'<div style="display:flex;align-items:flex-start;gap:14px"><div style="width:42px;height:42px;border-radius:11px;background:var(--errc);display:grid;place-items:center;flex-shrink:0"><span class="material-icons-round" style="color:var(--err);font-size:22px">error</span></div>'
      +'<div style="flex:1"><div style="font-family:var(--fd);font-weight:700;font-size:.95rem;color:var(--err);margin-bottom:4px">Error al consultar Gemini</div>'
      +'<div style="font-size:.72rem;color:var(--t2);margin-bottom:12px;font-family:Monaco,monospace;background:var(--s2);padding:10px 14px;border-radius:8px;word-break:break-word;white-space:pre-wrap;max-height:200px;overflow-y:auto">'+(errMsg||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</div>'
      +'<div style="display:flex;gap:8px;flex-wrap:wrap"><button onclick="window._agentGeminiPlan()" style="padding:8px 18px;border-radius:18px;border:none;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-family:var(--fd);font-size:.75rem;font-weight:500;cursor:pointer">Reintentar</button>'
      +'<button onclick="window._geminiOpenKeyModal()" style="padding:8px 18px;border-radius:18px;border:1.5px solid var(--ol);background:var(--s1);color:var(--t2);font-family:var(--fd);font-size:.75rem;font-weight:500;cursor:pointer">Cambiar API Key</button>'
      +'<button onclick="window.renderAgentPanel()" style="padding:8px 18px;border-radius:18px;border:1.5px solid var(--ol);background:var(--s1);color:var(--t2);font-family:var(--fd);font-size:.75rem;font-weight:500;cursor:pointer">Cancelar</button></div>'
      +'</div></div></div>';
  }

  // ── Apply category criteria locally to filter hosts ──
  function filterHostsByCriteria(profiles, criteria){
    if(!criteria) return [];
    var sevRank = {Low:1, Medium:2, High:3, Critical:4};
    return profiles.filter(function(p){
      if(criteria.estadoAD && criteria.estadoAD.length > 0 && criteria.estadoAD.indexOf(p.estadoAD) < 0) return false;
      if(criteria.minDiasLogon != null && p.diasLogon < criteria.minDiasLogon) return false;
      if(criteria.maxDiasLogon != null && p.diasLogon > criteria.maxDiasLogon) return false;
      if(criteria.minDiasQualys != null && p.diasQualys < criteria.minDiasQualys) return false;
      if(criteria.maxDiasQualys != null && p.diasQualys > criteria.maxDiasQualys) return false;
      if(criteria.soloKEV === true && p.kevs === 0) return false;
      if(criteria.severidadMin && sevRank[p.maxVPR] < sevRank[criteria.severidadMin]) return false;
      // Historical / temporal criteria
      if(criteria.soloNuevos === true && !p.isNew) return false;
      if(criteria.soloPersistentes === true && !p.isPersistent) return false;
      if(criteria.vulnDeltaMin != null && (p.vulnDelta||0) < criteria.vulnDeltaMin) return false;
      if(criteria.vulnDeltaMax != null && (p.vulnDelta||0) > criteria.vulnDeltaMax) return false;
      return true;
    });
  }

  var COLOR_MAP = {
    red:    {color:'var(--err)', bg:'var(--errc)', border:'var(--err)'},
    orange: {color:'#d97706',     bg:'rgba(217,119,6,.1)', border:'#d97706'},
    purple: {color:'#7c3aed',     bg:'rgba(124,58,237,.08)', border:'#7c3aed'},
    blue:   {color:'var(--p)',    bg:'var(--pc)',           border:'var(--p)'},
    green:  {color:'var(--ok)',   bg:'var(--okc)',          border:'var(--ok)'},
    cyan:   {color:'#0891b2',     bg:'rgba(8,145,178,.1)',  border:'#0891b2'}
  };

  // ── Render plan from Gemini (legacy single-call, no longer used) ──
  function _renderPlanLegacy_unused(area, plan){
    var profiles = window._agentProfiles || [];
    var ctx = window._agentContext;
    var statusColor = plan.estadoSLA === 'OK' ? 'var(--ok)' : plan.estadoSLA === 'EN_RIESGO' ? 'var(--warn)' : 'var(--err)';
    var statusBg = plan.estadoSLA === 'OK' ? 'var(--okc)' : plan.estadoSLA === 'EN_RIESGO' ? 'var(--warnc)' : 'var(--errc)';

    var html = '';

    // ─── Diagnosis card ───
    html += '<div style="background:linear-gradient(135deg,rgba(124,58,237,.06),var(--s1));border:1px solid rgba(124,58,237,.2);border-radius:var(--r);padding:22px 26px;margin-bottom:18px;box-shadow:var(--e1)">'
      +'<div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid rgba(124,58,237,.15)">'
      +'<div style="width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;flex-shrink:0"><span class="material-icons-round" style="color:#fff;font-size:22px">auto_awesome</span></div>'
      +'<div style="flex:1"><div style="font-family:var(--fd);font-weight:700;font-size:1rem">Diagnóstico del Especialista IA</div><div style="font-size:.65rem;color:var(--t2)">Modelo: '+(window._geminiActiveModel||'gemini-3-flash-preview')+' · Análisis basado en '+profiles.length+' dispositivos</div></div>'
      +'<div style="display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:18px;background:'+statusBg+';color:'+statusColor+';font-family:var(--fd);font-weight:700;font-size:.72rem"><span class="material-icons-round" style="font-size:14px">'+(plan.estadoSLA==='OK'?'check_circle':'warning')+'</span>'+(plan.estadoSLA||'').replace('_',' ')+'</div>'
      +'<button onclick="window._agentGeminiPlan()" title="Regenerar plan" style="background:none;border:none;cursor:pointer;color:var(--t2);width:32px;height:32px;border-radius:50%;display:grid;place-items:center;transition:all .15s" onmouseover="this.style.background=\'var(--s2)\';this.style.color=\'#7c3aed\'" onmouseout="this.style.background=\'transparent\';this.style.color=\'var(--t2)\'"><span class="material-icons-round" style="font-size:18px">refresh</span></button>'
      +'</div>'
      +'<div style="font-size:.85rem;line-height:1.65;color:var(--t)">'+escapeHtml(plan.diagnostico||'')+'</div>'
      +'</div>';

    // ─── Recomendación inmediata + Quick Wins side by side ───
    html += '<div style="display:grid;grid-template-columns:1.3fr 1fr;gap:16px;margin-bottom:18px">';

    // Inmediata
    html += '<div style="background:linear-gradient(135deg,var(--errc),var(--s1));border:1px solid rgba(209,70,0,.25);border-radius:var(--r);padding:20px;box-shadow:var(--e1)">'
      +'<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px"><span class="material-icons-round" style="color:var(--err);font-size:22px">priority_high</span>'
      +'<span style="font-family:var(--fd);font-weight:700;font-size:.9rem;color:var(--err)">Empezar HOY</span></div>'
      +'<div style="font-size:.85rem;line-height:1.6;color:var(--t)">'+escapeHtml(plan.recomendacionInmediata||'')+'</div>'
      +(plan.proyeccionSLA ? '<div style="margin-top:12px;padding:10px 14px;background:rgba(255,255,255,.5);border-radius:8px;font-size:.72rem;color:var(--t2);line-height:1.5"><strong style="color:var(--t)">Proyección SLA:</strong> '+escapeHtml(plan.proyeccionSLA)+'</div>' : '')
      +'</div>';

    // Quick wins
    html += '<div style="background:linear-gradient(135deg,var(--okc),var(--s1));border:1px solid rgba(26,122,50,.25);border-radius:var(--r);padding:20px;box-shadow:var(--e1)">'
      +'<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px"><span class="material-icons-round" style="color:var(--ok);font-size:22px">bolt</span>'
      +'<span style="font-family:var(--fd);font-weight:700;font-size:.9rem;color:var(--ok)">Quick Wins</span></div>'
      +'<ul style="margin:0;padding:0;list-style:none">';
    (plan.quickWins||[]).forEach(function(qw, i){
      html += '<li style="font-size:.78rem;line-height:1.5;color:var(--t);padding:6px 0;border-bottom:'+(i<plan.quickWins.length-1?'1px solid rgba(26,122,50,.1)':'none')+';display:flex;gap:8px;align-items:flex-start"><span style="color:var(--ok);font-weight:700;flex-shrink:0">'+(i+1)+'.</span><span>'+escapeHtml(qw)+'</span></li>';
    });
    html += '</ul></div>';

    html += '</div>';

    // ─── Categorías ───
    html += '<div style="font-family:var(--fd);font-size:.88rem;font-weight:600;color:var(--t2);margin:24px 0 12px;display:flex;align-items:center;gap:8px;text-transform:uppercase;letter-spacing:.5px">'
      +'<span class="material-icons-round" style="font-size:18px;color:var(--p)">format_list_numbered</span>'
      +'Plan de Acción Priorizado'
      +'<span style="background:#7c3aed;color:#fff;font-size:.6rem;padding:2px 8px;border-radius:10px;margin-left:4px;font-weight:700">'+(plan.categorias||[]).length+' categorías</span>'
      +'<span style="flex:1;height:1px;background:linear-gradient(90deg,var(--olv),transparent);margin-left:8px"></span>'
      +'</div>';

    var sortedCats = (plan.categorias||[]).slice().sort(function(a,b){ return (a.prioridad||99) - (b.prioridad||99); });

    sortedCats.forEach(function(cat, idx){
      var meta = COLOR_MAP[cat.color] || COLOR_MAP.blue;
      var actualHosts = filterHostsByCriteria(profiles, cat.criterios);
      var realCount = actualHosts.length;
      var effortIcon = cat.esfuerzo==='low'?'🟢':cat.esfuerzo==='medium'?'🟡':'🔴';
      var impactIcon = cat.impactoSLA==='high'?'⭐⭐⭐':cat.impactoSLA==='medium'?'⭐⭐':'⭐';

      html += '<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);margin-bottom:12px;overflow:hidden;border-left:4px solid '+meta.border+';transition:all .25s" onmouseover="this.style.boxShadow=\'var(--e2)\'" onmouseout="this.style.boxShadow=\'var(--e1)\'">';

      // Header (clickable)
      html += '<div style="padding:16px 20px;cursor:pointer;display:flex;align-items:center;gap:14px" onclick="window._agentToggleCat('+idx+')">';

      // Priority number + icon
      html += '<div style="display:flex;align-items:center;gap:10px;flex-shrink:0">'
        +'<div style="width:32px;height:32px;border-radius:50%;background:'+meta.color+';color:#fff;display:grid;place-items:center;font-family:var(--fd);font-weight:700;font-size:.85rem">'+(cat.prioridad||idx+1)+'</div>'
        +'<div style="width:42px;height:42px;border-radius:11px;background:'+meta.bg+';display:grid;place-items:center"><span class="material-icons-round" style="font-size:22px;color:'+meta.color+'">'+escapeAttr(cat.icono||'label')+'</span></div>'
        +'</div>';

      // Title + meta
      html += '<div style="flex:1;min-width:0">'
        +'<div style="font-family:var(--fd);font-size:1rem;font-weight:600;margin-bottom:3px">'+escapeHtml(cat.nombre||'')+'</div>'
        +'<div style="font-size:.72rem;color:var(--t2);display:flex;gap:14px;flex-wrap:wrap">'
        +'<span><strong style="color:var(--t)">'+realCount+'</strong> dispositivos reales</span>'
        +(cat.estimacionHosts && cat.estimacionHosts !== realCount ? '<span style="color:var(--t2)">(IA estimó '+cat.estimacionHosts+')</span>' : '')
        +'<span>Esfuerzo: '+effortIcon+' '+cat.esfuerzo+'</span>'
        +'<span>Impacto SLA: '+impactIcon+'</span>'
        +'</div></div>';

      // Count
      html += '<div style="text-align:center;flex-shrink:0"><div style="font-family:var(--fd);font-weight:700;font-size:1.6rem;color:'+meta.color+';line-height:1;letter-spacing:-.3px">'+realCount+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">hosts</div></div>';

      html += '<span class="material-icons-round" id="agentChev-'+idx+'" style="font-size:22px;color:var(--t2);transition:transform .2s;flex-shrink:0">expand_more</span>';
      html += '</div>';

      // Body (collapsed by default, except first one)
      var startOpen = idx === 0 ? 'block' : 'none';
      html += '<div id="agentBody-'+idx+'" style="display:'+startOpen+';border-top:1px solid var(--olv);padding:18px 20px;background:var(--s)">';

      // Action plan box
      html += '<div style="background:'+meta.bg+';border-left:3px solid '+meta.border+';padding:14px 18px;border-radius:0 8px 8px 0;margin-bottom:14px">'
        +'<div style="font-size:.6rem;text-transform:uppercase;letter-spacing:.5px;color:'+meta.color+';font-weight:700;margin-bottom:5px">Plan de Acción</div>'
        +'<div style="font-family:var(--fd);font-size:.92rem;font-weight:600;color:var(--t);margin-bottom:8px">'+escapeHtml(cat.accion||'')+'</div>'
        +'<div style="font-size:.75rem;color:var(--t2);line-height:1.6">'+escapeHtml(cat.razon||'')+'</div>'
        +'</div>';

      // Criteria explanation
      var critPills = [];
      var c = cat.criterios || {};
      if(c.estadoAD && c.estadoAD.length > 0) critPills.push('Estado: '+c.estadoAD.join('/'));
      if(c.minDiasLogon != null) critPills.push('Logon ≥'+c.minDiasLogon+'d');
      if(c.maxDiasLogon != null) critPills.push('Logon ≤'+c.maxDiasLogon+'d');
      if(c.minDiasQualys != null) critPills.push('Qualys ≥'+c.minDiasQualys+'d');
      if(c.maxDiasQualys != null) critPills.push('Qualys ≤'+c.maxDiasQualys+'d');
      if(c.soloKEV) critPills.push('Solo KEV');
      if(c.severidadMin) critPills.push('Severidad ≥'+c.severidadMin);
      if(c.soloNuevos) critPills.push('🆕 Recién aparecidos');
      if(c.soloPersistentes) critPills.push('🔁 Persistentes');
      if(c.vulnDeltaMin != null && c.vulnDeltaMin > 0) critPills.push('+'+c.vulnDeltaMin+' vulns vs anterior');
      if(c.vulnDeltaMax != null && c.vulnDeltaMax < 0) critPills.push(c.vulnDeltaMax+' vulns vs anterior');
      if(critPills.length > 0){
        html += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px"><span style="font-size:.62rem;color:var(--t2);text-transform:uppercase;letter-spacing:.4px;font-weight:600;align-self:center;margin-right:4px">Filtro:</span>';
        critPills.forEach(function(p){
          html += '<span style="padding:3px 10px;background:var(--s2);border-radius:14px;font-size:.66rem;color:var(--t2);font-family:var(--fd)">'+escapeHtml(p)+'</span>';
        });
        html += '</div>';
      }

      // Sample hosts
      if(realCount > 0){
        var sampleHosts = actualHosts.slice(0, 10);
        html += '<div style="font-size:.65rem;color:var(--t2);font-weight:600;text-transform:uppercase;letter-spacing:.3px;margin-bottom:8px">Dispositivos en esta categoría ('+Math.min(10,realCount)+' de '+realCount+')</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px">';
        sampleHosts.forEach(function(h){
          html += '<div style="background:var(--s1);border:1px solid var(--olv);border-radius:8px;padding:8px 12px;font-size:.7rem">'
            +'<div style="display:flex;justify-content:space-between;align-items:center;gap:6px;margin-bottom:3px">'
            +'<span style="font-family:var(--fd);font-weight:600;font-size:.74rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(h.hostname)+'</span>'
            +(h.kevs>0?'<span style="background:#dc2626;color:#fff;padding:1px 6px;border-radius:8px;font-size:.55rem;font-weight:700">KEV</span>':'')
            +'</div>'
            +'<div style="display:flex;gap:6px;color:var(--t2);font-size:.62rem;flex-wrap:wrap">'
            +'<span>'+escapeHtml(h.entorno)+'</span><span>·</span>'
            +'<span>'+h.vulns+' vulns</span><span>·</span>'
            +'<span>Q: '+h.diasQualys+'d</span><span>·</span>'
            +'<span>AD: '+h.diasLogon+'d</span>'
            +'</div></div>';
        });
        html += '</div>';
        if(realCount > 10){
          html += '<div style="text-align:center;margin-top:10px;font-size:.7rem;color:var(--t2)">... y '+(realCount-10)+' dispositivos más</div>';
        }

        // Export button
        html += '<div style="margin-top:14px"><button onclick="window._agentExportCatGemini('+idx+')" style="display:inline-flex;align-items:center;gap:5px;padding:7px 16px;border-radius:18px;border:1.5px solid '+meta.border+';background:transparent;color:'+meta.color+';font-family:var(--fd);font-size:.72rem;font-weight:500;cursor:pointer;transition:all .2s"><span class="material-icons-round" style="font-size:14px">download</span>Exportar lista CSV</button></div>';
      } else {
        html += '<div style="text-align:center;padding:20px;color:var(--t2);font-size:.78rem;background:var(--s2);border-radius:8px"><span class="material-icons-round" style="font-size:20px;display:block;margin-bottom:6px;opacity:.4">inbox</span>Ningún dispositivo cumple los criterios de esta categoría en tu parque actual</div>';
      }

      html += '</div>'; // body
      html += '</div>'; // card
    });

    area.innerHTML = html;
    area.scrollIntoView({behavior:'smooth', block:'start'});
  }

  window._agentToggleCat = function(idx){
    var body = document.getElementById('agentBody-'+idx);
    var chev = document.getElementById('agentChev-'+idx);
    if(!body) return;
    var open = body.style.display === 'block';
    body.style.display = open ? 'none' : 'block';
    if(chev) chev.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
  };

  // SLA Simulator: recalculate based on selected categories
  window._agentSimCalc = function(){
    var ctx = window._agentContext; if(!ctx) return;
    var checks = document.querySelectorAll('#agentSimulator input[type=checkbox]:checked');
    var totalCleaned = 0;
    checks.forEach(function(c){ totalCleaned += parseInt(c.dataset.count)||0; });

    var newCount = Math.max(ctx.sla.dispositivosVulnerables - totalCleaned, 0);
    var newPct = ctx.sla.totalDispositivosParque > 0 ? (newCount/ctx.sla.totalDispositivosParque*100) : 0;
    var willPass = newPct < 5;
    var currentlyPasses = ctx.sla.actualPct < 5;

    var toEl = document.getElementById('agSimTo');
    var toHostsEl = document.getElementById('agSimToHosts');
    var msgEl = document.getElementById('agSimMsg');
    var badgeEl = document.getElementById('agSimBadge');

    if(toEl){
      if(checks.length === 0){
        toEl.textContent = '--';
        toEl.style.color = 'var(--t2)';
      } else {
        toEl.textContent = newPct.toFixed(2)+'%';
        toEl.style.color = willPass ? 'var(--ok)' : 'var(--err)';
      }
    }
    if(toHostsEl){
      toHostsEl.textContent = checks.length === 0 ? '--' : newCount + ' hosts';
    }
    if(msgEl){
      if(checks.length === 0){
        msgEl.innerHTML = 'Marca categorías arriba para simular el impacto en el SLA';
      } else if(willPass && !currentlyPasses){
        msgEl.innerHTML = '<strong style="color:var(--ok)">✓ Cumplirías el SLA Cajamar</strong> &middot; Eliminando <strong>'+totalCleaned+'</strong> dispositivos con <strong>'+checks.length+' acción'+(checks.length>1?'es':'')+'</strong>';
      } else if(willPass && currentlyPasses){
        var savedExtra = ctx.sla.actualPct - newPct;
        msgEl.innerHTML = '<strong style="color:var(--ok)">SLA seguiría cumplido</strong> &middot; Margen extra de <strong>'+savedExtra.toFixed(2)+'%</strong> &middot; '+totalCleaned+' hosts limpiados';
      } else {
        var stillNeed = newCount - Math.floor(ctx.sla.totalDispositivosParque * 0.05);
        msgEl.innerHTML = '<strong style="color:var(--err)">Aún por encima del 5%</strong> &middot; Necesitas <strong>'+stillNeed+'</strong> dispositivos más para llegar al objetivo';
      }
    }
    if(badgeEl){
      if(checks.length === 0){
        badgeEl.innerHTML = '';
      } else {
        badgeEl.innerHTML = '<div style="display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:20px;background:'+(willPass?'var(--okc)':'var(--errc)')+';color:'+(willPass?'var(--ok)':'var(--err)')+';font-family:var(--fd);font-weight:700;font-size:.78rem"><span class="material-icons-round" style="font-size:16px">'+(willPass?'check_circle':'warning')+'</span>'+(willPass?'SLA OK':'SLA NO')+'</div>';
      }
    }
  };

  window._agentExportCatGemini = function(idx){
    var plan = window._agentPlan; if(!plan) return;
    var profiles = window._agentProfiles || [];
    var sortedCats = plan.categorias.slice().sort(function(a,b){ return (a.prioridad||99) - (b.prioridad||99); });
    var cat = sortedCats[idx]; if(!cat) return;
    var hosts = filterHostsByCriteria(profiles, cat.criterios);
    var lines = ['Hostname;Entorno;Estado AD;Días Logon;Días Qualys;Vulnerabilidades;KEVs;Severidad Máx;Acción Recomendada'];
    hosts.forEach(function(h){
      lines.push([h.hostname, h.entorno, h.estadoAD, h.diasLogon, h.diasQualys, h.vulns, h.kevs, h.maxVPR, cat.accion].join(';'));
    });
    var blob = new Blob(['\uFEFF'+lines.join('\n')], {type:'text/csv;charset=utf-8'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'plan_'+(cat.id||'cat'+idx)+'_'+new Date().toISOString().split('T')[0]+'.csv';
    a.click();
  };

  function escapeHtml(s){
    if(s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function escapeAttr(s){
    if(s == null) return '';
    return String(s).replace(/[^a-z_]/gi, '');
  }

  // ── Progressive Markdown parser (vanilla, Streamdown-style) ──
  // Re-parses the FULL accumulated text on each chunk update.
  // Handles incomplete states: open ** without close stays as text until close arrives.
  // Numbered list items use a manual counter that survives across paragraphs (only resets on heading).
  function mdToHtml(md){
    if(!md) return '';

    function inline(text){
      var t = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      t = t.replace(/`([^`]+)`/g, '<code style="background:rgba(124,58,237,.1);color:#7c3aed;padding:1px 6px;border-radius:4px;font-family:Monaco,monospace;font-size:.88em">$1</code>');
      t = t.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
      t = t.replace(/(^|[^*])\*([^*\n]+)\*([^*]|$)/g, '$1<em>$2</em>$3');
      t = t.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" style="color:#7c3aed;text-decoration:none;border-bottom:1px dotted #7c3aed">$1</a>');
      return t;
    }

    var lines = md.split('\n');
    var html = '';
    var inUlList = false;
    var paraBuffer = [];
    var orderedCounter = 0; // Sequential counter for numbered items, persists across paragraphs

    function closeUl(){
      if(inUlList){ html += '</ul>'; inUlList = false; }
    }
    function flushPara(){
      if(paraBuffer.length > 0){
        html += '<p style="margin:8px 0;line-height:1.65">' + inline(paraBuffer.join(' ')) + '</p>';
        paraBuffer = [];
      }
    }
    function resetOrdered(){ orderedCounter = 0; }

    for(var i=0; i<lines.length; i++){
      var line = lines[i];
      var trimmed = line.replace(/\s+$/, '');

      // Empty line — paragraph break (does NOT reset numbered counter)
      if(trimmed === ''){
        flushPara();
        closeUl();
        continue;
      }

      // Headings (reset numbered counter — new section starts)
      if(/^####\s+/.test(trimmed)){ flushPara(); closeUl(); resetOrdered(); html += '<h4 style="font-family:var(--fd);font-size:.85rem;font-weight:700;margin:14px 0 6px;color:var(--t)">' + inline(trimmed.replace(/^####\s+/, '')) + '</h4>'; continue; }
      if(/^###\s+/.test(trimmed)){ flushPara(); closeUl(); resetOrdered(); html += '<h3 style="font-family:var(--fd);font-size:.95rem;font-weight:700;margin:16px 0 8px;color:#7c3aed">' + inline(trimmed.replace(/^###\s+/, '')) + '</h3>'; continue; }
      if(/^##\s+/.test(trimmed)){ flushPara(); closeUl(); resetOrdered(); html += '<h2 style="font-family:var(--fd);font-size:1.05rem;font-weight:700;margin:20px 0 10px;color:var(--t);display:flex;align-items:center;gap:8px"><span style="width:4px;height:18px;background:#7c3aed;border-radius:2px;flex-shrink:0"></span>' + inline(trimmed.replace(/^##\s+/, '')) + '</h2>'; continue; }
      if(/^#\s+/.test(trimmed)){ flushPara(); closeUl(); resetOrdered(); html += '<h1 style="font-family:var(--fd);font-size:1.2rem;font-weight:700;margin:22px 0 12px;letter-spacing:-.3px">' + inline(trimmed.replace(/^#\s+/, '')) + '</h1>'; continue; }

      // Horizontal rule
      if(/^---+$/.test(trimmed) || /^\*\*\*+$/.test(trimmed)){
        flushPara(); closeUl();
        html += '<hr style="border:none;border-top:1px solid var(--olv);margin:14px 0">';
        continue;
      }

      // Blockquote
      var bq = trimmed.match(/^>\s+(.+)$/);
      if(bq){
        flushPara(); closeUl();
        html += '<blockquote style="border-left:3px solid #7c3aed;padding:8px 14px;margin:8px 0;background:rgba(124,58,237,.06);border-radius:0 8px 8px 0;font-size:.85em;color:var(--t2)">' + inline(bq[1]) + '</blockquote>';
        continue;
      }

      // Unordered list
      var ulm = trimmed.match(/^[\-\*+]\s+(.+)$/);
      if(ulm){
        flushPara();
        if(!inUlList){ html += '<ul style="margin:6px 0 10px 0;padding-left:22px">'; inUlList = true; }
        html += '<li style="margin:4px 0;line-height:1.55">' + inline(ulm[1]) + '</li>';
        continue;
      }

      // Ordered list — render as styled badge block (counter survives across paragraphs)
      var olm = trimmed.match(/^(\d+)\.\s+(.+)$/);
      if(olm){
        flushPara();
        closeUl();
        orderedCounter++;
        html += '<div style="display:flex;gap:12px;margin:10px 0;align-items:flex-start">'
          + '<span style="flex-shrink:0;width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;display:grid;place-items:center;font-family:var(--fd);font-weight:700;font-size:.75rem;box-shadow:0 2px 6px rgba(124,58,237,.3);margin-top:1px">'
          + orderedCounter
          + '</span>'
          + '<div style="flex:1;min-width:0;line-height:1.6;padding-top:2px">' + inline(olm[2]) + '</div>'
          + '</div>';
        continue;
      }

      // Regular paragraph line — accumulate
      closeUl();
      paraBuffer.push(trimmed);
    }

    flushPara();
    closeUl();
    return html;
  }

  window._agentMdToHtml = mdToHtml; // exposed for debugging
})();
