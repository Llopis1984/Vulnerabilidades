// ANÁLISIS ESTRATÉGICO — Risk Operations Center style
// Inyecta KPIs estratégicos, tendencias y riesgo por entorno encima del contenido existente
(function(){
  var _rendered = false;

  function normSev(vpr){
    if(!vpr) return 'Low';
    var v = vpr.toLowerCase();
    // "Rating 9.0 a 10.0" → Critical, "Rating 7.0 a 8.9" → High
    if(v.indexOf('9.0')>=0 || v.indexOf('10')>=0) return 'Critical';
    if(v.indexOf('7.0')>=0 || v.indexOf('8.')>=0) return 'High';
    if(v.indexOf('4.')>=0 || v.indexOf('5.')>=0 || v.indexOf('6.')>=0) return 'Medium';
    return 'Low';
  }

  // SVG gauge (semicircle)
  function gauge(score, max, size, label){
    max = max || 100; size = size || 120;
    var r = (size/2) - 6, c = Math.PI * r;
    var pct = Math.min(score / max, 1);
    var color = pct >= 0.7 ? 'var(--err)' : pct >= 0.4 ? 'var(--warn)' : 'var(--ok)';
    return '<div style="text-align:center">'
      +'<svg width="'+size+'" height="'+(size/2+12)+'" viewBox="0 0 '+size+' '+(size/2+12)+'">'
      +'<path d="M6,'+(size/2+6)+' A'+r+','+r+' 0 0,1 '+(size-6)+','+(size/2+6)+'" fill="none" stroke="var(--s2)" stroke-width="8" stroke-linecap="round"/>'
      +'<path d="M6,'+(size/2+6)+' A'+r+','+r+' 0 0,1 '+(size-6)+','+(size/2+6)+'" fill="none" stroke="'+color+'" stroke-width="8" stroke-linecap="round" stroke-dasharray="'+c+'" stroke-dashoffset="'+(c*(1-pct))+'" style="transition:stroke-dashoffset 1s ease"/>'
      +'<text x="'+(size/2)+'" y="'+(size/2-2)+'" text-anchor="middle" font-family="var(--fd)" font-size="'+(size/3.5)+'" font-weight="700" fill="var(--t)">'+score+'</text>'
      +'<text x="'+(size/2)+'" y="'+(size/2+14)+'" text-anchor="middle" font-family="var(--fd)" font-size="10" fill="var(--t2)">de '+max+'</text>'
      +'</svg>'
      +'<div style="font-size:.62rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-top:4px">'+label+'</div></div>';
  }

  // Sparkline SVG
  function sparkline(values, w, h, color){
    w = w || 120; h = h || 32;
    if(!values || values.length < 2) return '';
    var max = Math.max.apply(null, values), min = Math.min.apply(null, values);
    var range = max - min || 1;
    var pts = values.map(function(v, i){
      return Math.round(i/(values.length-1)*w)+','+Math.round(h - (v-min)/range*(h-4) + 2);
    }).join(' ');
    return '<svg width="'+w+'" height="'+h+'" viewBox="0 0 '+w+' '+h+'" style="display:block">'
      +'<polyline points="'+pts+'" fill="none" stroke="'+color+'" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
      +'<circle cx="'+Math.round(w)+'" cy="'+pts.split(' ').pop().split(',')[1]+'" r="3" fill="'+color+'"/>'
      +'</svg>';
  }

  // Bullet chart (bar with threshold marker)
  function bulletChart(value, threshold, max, color){
    max = max || 100;
    var pct = Math.min(value/max*100, 100);
    var thPct = Math.min(threshold/max*100, 100);
    return '<div style="position:relative;height:14px;background:var(--s2);border-radius:7px;overflow:visible">'
      +'<div style="height:100%;width:'+pct+'%;background:'+color+';border-radius:7px;transition:width .6s"></div>'
      +'<div style="position:absolute;top:-2px;left:'+thPct+'%;width:2px;height:18px;background:var(--t);border-radius:1px" title="Umbral: '+threshold+'"></div>'
      +'</div>';
  }

  window.renderAnalysisStrategic = function(){
    var ct = document.getElementById('ct-analysis');
    if(!ct) return;
    var raw = window._raw;
    if(!raw || !raw.length){ ct.innerHTML=''; return; }

    // ═══ CALCULATE STRATEGIC METRICS ═══
    var hostMap = {};
    var envMap = {};
    var torreMap = {};
    var sevMap = {Critical:0, High:0, Medium:0, Low:0};
    var totalVulns = raw.length;
    var kevCount = 0;

    raw.forEach(function(r){
      // Per host
      if(!hostMap[r.hostname]) hostMap[r.hostname] = {vulns:0, maxDias:0, maxLogon:0, env:r.entorno, estado:r.estadoAD, isKEV:false};
      var h = hostMap[r.hostname];
      h.vulns++;
      if(r.diasQualys > h.maxDias) h.maxDias = r.diasQualys;
      if(r.diasLogon > h.maxLogon) h.maxLogon = r.diasLogon;
      if(r.isKEV){ h.isKEV = true; kevCount++; }

      // Per environment
      var env = r.entorno || 'Sin clasificar';
      if(!envMap[env]) envMap[env] = {hosts:new Set(), vulns:0, criticals:0, kevs:0, totalDias:0, habilitados:0};
      var e = envMap[env];
      e.hosts.add(r.hostname);
      e.vulns++;
      if(normSev(r.nivelVPR)==='Critical') e.criticals++;
      if(r.isKEV) e.kevs++;
      e.totalDias += (r.diasQualys||0);
      if(r.estadoAD==='HABILITADO') e.habilitados++;

      // Per torre
      var torre = r.torre || 'Sin clasificar';
      if(!torreMap[torre]) torreMap[torre] = {hosts:new Set(), vulns:0, criticals:0, kevs:0, totalDias:0};
      var tt = torreMap[torre];
      tt.hosts.add(r.hostname);
      tt.vulns++;
      if(normSev(r.nivelVPR)==='Critical') tt.criticals++;
      if(r.isKEV) tt.kevs++;
      tt.totalDias += (r.diasQualys||0);

      // Severity
      sevMap[normSev(r.nivelVPR)]++;
    });

    var totalHosts = Object.keys(hostMap).length;
    var totalDevices = window.totalDevices || totalHosts;
    var avgDias = totalVulns > 0 ? Math.round(raw.reduce(function(s,r){return s+(r.diasQualys||0);},0)/totalVulns) : 0;
    var vulnsPerHost = totalHosts > 0 ? (totalVulns/totalHosts).toFixed(1) : 0;

    // Risk score (0-1000 scale like Qualys TruRisk)
    var criticalHosts = Object.values(hostMap).filter(function(h){ return h.estado==='HABILITADO' && h.maxDias>15 && h.maxLogon>15; }).length;
    var riskScore = Math.min(Math.round(
      (sevMap.Critical/totalVulns*400) +
      (kevCount/totalVulns*200) +
      (avgDias/30*150) +
      (criticalHosts/totalHosts*250)
    ), 1000);

    // SLA
    var slaData = null; try{slaData=JSON.parse(localStorage.getItem('sla_thresholds_v1')||'null');}catch(e){}
    var slaOK=0, slaBreach=0;
    if(slaData){ raw.forEach(function(r){var lv=normSev(r.nivelVPR)==='Critical'?'critical':normSev(r.nivelVPR)==='High'?'high':'medium';if(r.diasQualys<=(slaData[lv]||90))slaOK++;else slaBreach++;}); }
    var slaPct = totalVulns>0&&slaData ? Math.round(slaOK/totalVulns*100) : null;

    // Snapshots trend data
    var snaps = window._snapshots || [];
    var trendValues = snaps.map(function(s){ return s.totalV; });
    var trendHosts = snaps.map(function(s){ return s.totalH; });

    // ═══ BUILD HTML ═══
    var html = '<div style="max-width:1440px;margin:0 auto;padding:0 0 20px">';

    // HEADER
    html+='<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:22px">'
      +'<div><div style="font-family:var(--fd);font-size:1.2rem;font-weight:700;display:flex;align-items:center;gap:10px;letter-spacing:-.3px"><span class="material-icons-round" style="color:var(--p);font-size:26px">hub</span>Centro de Operaciones de Riesgo</div>'
      +'<div style="font-size:.73rem;color:var(--t2);margin-top:4px">Visión estratégica del estado de seguridad · Métricas de decisión · Riesgo por entorno'
      +' <span class="material-icons-round" style="font-size:15px;color:var(--p);cursor:pointer;vertical-align:-3px" onclick="window._showInfoPop(this,\'Índice TruRisk (0-1000)\',[[\' % Severidad crítica (VPR 9.0+)\',\'400pts\',\'var(--err)\'],[\' % instancias CISA KEV\',\'200pts\',\'var(--err)\'],[\' Antigüedad media (30d=máx)\',\'150pts\',\'var(--warn)\'],[\' % Hosts críticos (Q+AD)\',\'250pts\']],\'Escala: <span style=color:var(--ok)>■</span> 0-300 Bajo &nbsp;<span style=color:var(--warn)>■</span> 300-700 Medio &nbsp;<span style=color:var(--err)>■</span> 700+ Alto\')">info_outline</span>'
      +'</div></div>'
      +'</div>';

    // ═══ ROW 1: Risk Score + KPIs ═══
    html+='<div style="display:grid;grid-template-columns:280px 1fr;gap:16px;margin-bottom:18px">';

    // Risk gauge card
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:24px;text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center">'
      +gauge(riskScore, 1000, 140, 'Índice TruRisk')
      +'<div style="display:flex;gap:12px;margin-top:14px;font-size:.62rem">'
      +'<span style="color:var(--ok)">■ 0-300 Bajo</span>'
      +'<span style="color:var(--warn)">■ 300-700 Medio</span>'
      +'<span style="color:var(--err)">■ 700+ Alto</span>'
      +'</div></div>';

    // KPI grid
    html+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px">';

    // KPI 1: Vulns abiertas
    var vulnTrend = trendValues.length>=2 ? (trendValues[trendValues.length-1] - trendValues[trendValues.length-2]) : 0;
    var vulnArrow = vulnTrend > 0 ? '▲' : vulnTrend < 0 ? '▼' : '—';
    var vulnColor = vulnTrend > 0 ? 'var(--err)' : vulnTrend < 0 ? 'var(--ok)' : 'var(--t2)';
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:16px 18px;position:relative;overflow:hidden">'
      +'<div style="font-size:.58rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">Vulns Abiertas</div>'
      +'<div style="display:flex;align-items:baseline;gap:8px"><span style="font-family:var(--fd);font-size:1.8rem;font-weight:700;letter-spacing:-.5px">'+totalVulns.toLocaleString()+'</span>'
      +'<span style="font-size:.72rem;font-weight:600;color:'+vulnColor+'">'+vulnArrow+' '+Math.abs(vulnTrend)+'</span></div>'
      +(trendValues.length>=2?'<div style="margin-top:6px">'+sparkline(trendValues, 100, 24, 'var(--err)')+'</div>':'')
      +'</div>';

    // KPI 2: Hosts afectados
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:16px 18px">'
      +'<div style="font-size:.58rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">Hosts en Riesgo</div>'
      +'<div style="display:flex;align-items:baseline;gap:8px"><span style="font-family:var(--fd);font-size:1.8rem;font-weight:700;letter-spacing:-.5px">'+totalHosts+'</span>'
      +'<span style="font-size:.72rem;color:var(--t2)">de '+totalDevices+'</span></div>'
      +'<div style="margin-top:8px">'+bulletChart(totalHosts, Math.round(totalDevices*0.05), totalDevices, 'var(--err)')+'</div>'
      +'<div style="font-size:.58rem;color:var(--t2);margin-top:3px">Umbral: 5% del parque</div>'
      +'</div>';

    // KPI 3: MTTR / Avg Days
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:16px 18px">'
      +'<div style="font-size:.58rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">Antigüedad Media</div>'
      +'<div style="font-family:var(--fd);font-size:1.8rem;font-weight:700;letter-spacing:-.5px;color:'+(avgDias>30?'var(--err)':avgDias>15?'var(--warn)':'var(--ok)')+'">'+avgDias+'<span style="font-size:.9rem;font-weight:500">d</span></div>'
      +'<div style="font-size:.62rem;color:var(--t2);margin-top:4px">'+vulnsPerHost+' vulns/host</div>'
      +'</div>';

    // KPI 4: SLA
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:16px 18px">'
      +'<div style="font-size:.58rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">SLA Compliance</div>';
    if(slaPct !== null){
      html+='<div style="font-family:var(--fd);font-size:1.8rem;font-weight:700;letter-spacing:-.5px;color:'+(slaPct>=80?'var(--ok)':slaPct>=50?'var(--warn)':'var(--err)')+'">'+slaPct+'<span style="font-size:.9rem;font-weight:500">%</span></div>'
        +'<div style="font-size:.62rem;color:var(--t2);margin-top:4px">'+slaBreach+' incumplimientos</div>';
    } else {
      html+='<div style="font-family:var(--fd);font-size:1rem;font-weight:500;color:var(--t2);margin-top:6px">No configurado</div>';
    }
    html+='</div>';

    // KPI 5: KEV
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:16px 18px">'
      +'<div style="font-size:.58rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px">CISA KEV</div>'
      +'<div style="font-family:var(--fd);font-size:1.8rem;font-weight:700;letter-spacing:-.5px;color:'+(kevCount>0?'var(--err)':'var(--ok)')+'">'+kevCount+'</div>'
      +'<div style="font-size:.62rem;color:var(--t2);margin-top:4px">instancias explotables</div>'
      +'</div>';

    html+='</div></div>'; // end KPI grid + row

    // ═══ ROW 2: Top Risk Factors + Severity ═══
    html+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px">';

    // Risk factors
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px">'
      +'<h3 style="font-family:var(--fd);font-size:.88rem;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:20px;color:var(--err)">warning</span>Factores de Riesgo Principales</h3>';

    var factors = [
      {icon:'shield', label:'CISA KEV Activos', value:kevCount, desc:'Exploits confirmados en producción', color:'#dc2626'},
      {icon:'devices', label:'Hosts Críticos', value:criticalHosts, desc:'Superan umbrales Q+AD simultáneamente', color:'var(--err)'},
      {icon:'schedule', label:'Antigüedad >30d', value:raw.filter(function(r){return r.diasQualys>30;}).length, desc:'Vulnerabilidades sin parchear >30 días', color:'var(--warn)'},
      {icon:'trending_up', label:'Vulns/Host Media', value:vulnsPerHost, desc:'Densidad de exposición por equipo', color:'var(--p)'}
    ];
    factors.forEach(function(f){
      html+='<div style="display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;margin-bottom:6px;background:var(--s2);transition:all .2s" onmouseover="this.style.transform=\'translateX(4px)\'" onmouseout="this.style.transform=\'none\'">'
        +'<span class="material-icons-round" style="font-size:20px;color:'+f.color+';flex-shrink:0">'+f.icon+'</span>'
        +'<div style="flex:1"><div style="font-family:var(--fd);font-size:.78rem;font-weight:600">'+f.label+'</div><div style="font-size:.62rem;color:var(--t2)">'+f.desc+'</div></div>'
        +'<div style="font-family:var(--fd);font-size:1.2rem;font-weight:700;color:'+f.color+';flex-shrink:0">'+f.value+'</div>'
        +'</div>';
    });
    html+='</div>';

    // Severity breakdown
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px">'
      +'<h3 style="font-family:var(--fd);font-size:.88rem;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:20px;color:var(--p)">donut_large</span>Distribución de Severidad</h3>';

    // Mini stacked bar
    var sevColors = {Critical:'var(--err)', High:'var(--warn)', Medium:'var(--p)', Low:'var(--ok)'};
    var sevLabels = {Critical:'Crítica', High:'Alta', Medium:'Media', Low:'Baja'};
    html+='<div style="display:flex;height:24px;border-radius:12px;overflow:hidden;margin-bottom:16px">';
    ['Critical','High','Medium','Low'].forEach(function(s){
      var pct = totalVulns>0 ? (sevMap[s]/totalVulns*100) : 0;
      if(pct > 0) html+='<div style="width:'+pct+'%;background:'+sevColors[s]+';transition:width .5s" title="'+sevLabels[s]+': '+sevMap[s]+'"></div>';
    });
    html+='</div>';

    ['Critical','High','Medium','Low'].forEach(function(s){
      var pct = totalVulns>0 ? Math.round(sevMap[s]/totalVulns*100) : 0;
      html+='<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">'
        +'<div style="width:10px;height:10px;border-radius:3px;background:'+sevColors[s]+';flex-shrink:0"></div>'
        +'<span style="font-size:.75rem;font-weight:500;width:50px">'+sevLabels[s]+'</span>'
        +'<div style="flex:1;height:8px;background:var(--s2);border-radius:4px;overflow:hidden"><div style="height:100%;width:'+pct+'%;background:'+sevColors[s]+';border-radius:4px;transition:width .5s"></div></div>'
        +'<span style="font-family:var(--fd);font-weight:700;font-size:.78rem;width:50px;text-align:right">'+sevMap[s]+'</span>'
        +'<span style="font-size:.62rem;color:var(--t2);width:30px">'+pct+'%</span>'
        +'</div>';
    });
    html+='</div>';
    html+='</div>'; // end row 2

    // ═══ ROW 3: Risk by Environment (bullet charts) ═══
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px;margin-bottom:18px">'
      +'<h3 style="font-family:var(--fd);font-size:.88rem;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:20px;color:var(--p)">apartment</span>Riesgo por Entorno</h3>';

    html+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px">';
    var envEntries = Object.entries(envMap).sort(function(a,b){ return b[1].vulns - a[1].vulns; });
    var maxEnvVulns = envEntries.length>0 ? envEntries[0][1].vulns : 1;
    var envColors = ['var(--p)','var(--err)','var(--warn)','var(--ok)','#7c3aed'];

    envEntries.forEach(function(entry, i){
      var name = entry[0], data = entry[1];
      var envRisk = Math.min(Math.round((data.vulns/maxEnvVulns)*80 + (data.kevs>0?20:0)), 100);
      var riskColor = envRisk >= 70 ? 'var(--err)' : envRisk >= 40 ? 'var(--warn)' : 'var(--ok)';
      var avgD = data.vulns>0 ? Math.round(data.totalDias/data.vulns) : 0;

      html+='<div style="background:var(--s2);border-radius:12px;padding:16px;border-left:4px solid '+(envColors[i%envColors.length])+'">'
        +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'
        +'<span style="font-family:var(--fd);font-size:.85rem;font-weight:600">'+name+'</span>'
        +'<span style="font-family:var(--fd);font-size:1.1rem;font-weight:700;color:'+riskColor+'">'+envRisk+'<span style="font-size:.65rem;font-weight:500;color:var(--t2)"> risk</span></span>'
        +'</div>'
        +bulletChart(envRisk, 50, 100, riskColor)
        +'<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:10px;text-align:center">'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem">'+data.hosts.size+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">Hosts</div></div>'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem">'+data.vulns+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">Vulns</div></div>'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem;color:'+(data.kevs>0?'var(--err)':'var(--ok)')+'">'+data.kevs+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">KEV</div></div>'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem">'+avgD+'d</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">Avg días</div></div>'
        +'</div></div>';
    });
    html+='</div></div>';

    // ═══ ROW 3bis: Riesgo por Torre ═══
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px;margin-bottom:18px">'
      +'<h3 style="font-family:var(--fd);font-size:.88rem;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:20px;color:var(--p)">groups</span>Riesgo por Torre</h3>';
    html+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px">';
    var torreEntries = Object.entries(torreMap).sort(function(a,b){ return b[1].vulns - a[1].vulns; });
    var maxTorreVulns = torreEntries.length>0 ? torreEntries[0][1].vulns : 1;
    var torreColors = ['var(--p)','var(--err)','var(--warn)','var(--ok)','#7c3aed','#0ea5e9'];
    torreEntries.forEach(function(entry, i){
      var name = entry[0], data = entry[1];
      var torreRisk = Math.min(Math.round((data.vulns/maxTorreVulns)*80 + (data.kevs>0?20:0)), 100);
      var riskColor = torreRisk >= 70 ? 'var(--err)' : torreRisk >= 40 ? 'var(--warn)' : 'var(--ok)';
      var avgD = data.vulns>0 ? Math.round(data.totalDias/data.vulns) : 0;
      html+='<div onclick="var t=document.querySelector(\'[data-view=towers]\');if(t){t.click();setTimeout(function(){if(window._towersDrill)window._towersDrill(\''+name.replace(/\'/g,"\\'")+'\')},100);}" style="background:var(--s2);border-radius:12px;padding:16px;border-left:4px solid '+(torreColors[i%torreColors.length])+';cursor:pointer;transition:transform .15s" onmouseover="this.style.transform=\'translateY(-2px)\'" onmouseout="this.style.transform=\'none\'" title="Click para ver detalle en panel Por Torre">'
        +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'
        +'<span style="font-family:var(--fd);font-size:.85rem;font-weight:600">'+name+'</span>'
        +'<span style="font-family:var(--fd);font-size:1.1rem;font-weight:700;color:'+riskColor+'">'+torreRisk+'<span style="font-size:.65rem;font-weight:500;color:var(--t2)"> risk</span></span>'
        +'</div>'
        +bulletChart(torreRisk, 50, 100, riskColor)
        +'<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:10px;text-align:center">'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem">'+data.hosts.size+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">Hosts</div></div>'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem">'+data.vulns+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">Vulns</div></div>'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem;color:'+(data.kevs>0?'var(--err)':'var(--ok)')+'">'+data.kevs+'</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">KEV</div></div>'
        +'<div><div style="font-family:var(--fd);font-weight:700;font-size:.85rem">'+avgD+'d</div><div style="font-size:.55rem;color:var(--t2);text-transform:uppercase">Avg días</div></div>'
        +'</div></div>';
    });
    html+='</div></div>';

    // ═══ ROW 4: RECOMMENDATIONS + WHAT-IF SIMULATOR ═══
    html+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px">';

    // ── Automated Recommendations ──
    // Build recommendation list from data analysis
    var recommendations = [];
    // Group vulns by name and sort by impact
    var recGroups = {};
    raw.forEach(function(r){
      var k = r.vulnName||''; if(!recGroups[k]) recGroups[k]={name:k,hosts:new Set(),kevs:0,crit:0,sol:r.solucion};
      recGroups[k].hosts.add(r.hostname);
      if(r.isKEV) recGroups[k].kevs++;
      if(normSev(r.nivelVPR)==='Critical') recGroups[k].crit++;
    });
    var recSorted = Object.values(recGroups).sort(function(a,b){
      var sa = a.hosts.size * (a.kevs>0?3:1) * (a.crit>0?2:1);
      var sb = b.hosts.size * (b.kevs>0?3:1) * (b.crit>0?2:1);
      return sb - sa;
    }).slice(0, 5);

    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px">'
      +'<h3 style="font-family:var(--fd);font-size:.88rem;font-weight:600;margin-bottom:14px;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:20px;color:var(--ok)">auto_awesome</span>Top 5 Acciones Recomendadas</h3>'
      +'<div style="font-size:.68rem;color:var(--t2);margin-bottom:14px">Acciones priorizadas por impacto: cada una muestra cuántos hosts y KEVs resuelve</div>';

    recSorted.forEach(function(r, i){
      var impact = r.hosts.size;
      var impactPct = Math.round(impact/totalHosts*100);
      var badges = '';
      if(r.kevs > 0) badges += '<span style="background:#dc2626;color:#fff;padding:1px 6px;border-radius:8px;font-size:.52rem;font-weight:700">KEV</span>';
      if(r.crit > 0) badges += '<span style="background:rgba(124,58,237,.12);color:#7c3aed;padding:1px 6px;border-radius:8px;font-size:.52rem;font-weight:600">Critical</span>';
      // Extract KB if available
      var kb = r.sol ? (r.sol.match(/KB\d{6,8}/i)||[''])[0] : '';

      html+='<div style="display:flex;gap:10px;align-items:flex-start;padding:10px 12px;border-radius:10px;margin-bottom:4px;background:var(--s2);transition:all .2s;cursor:default" onmouseover="this.style.transform=\'translateX(4px)\'" onmouseout="this.style.transform=\'none\'">'
        +'<div style="width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,var(--ok),var(--ok)44);display:grid;place-items:center;font-family:var(--fd);font-weight:700;font-size:.75rem;color:var(--ok);flex-shrink:0">'+(i+1)+'</div>'
        +'<div style="flex:1;min-width:0">'
        +'<div style="font-size:.75rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+r.name.substring(0,55)+(r.name.length>55?'...':'')+'</div>'
        +'<div style="display:flex;gap:6px;align-items:center;margin-top:3px;flex-wrap:wrap">'
        +'<span style="font-size:.62rem;color:var(--t2)"><strong style="color:var(--ok)">-'+impact+'</strong> hosts ('+impactPct+'%)</span>'
        +(r.kevs>0?'<span style="font-size:.62rem;color:var(--t2)"><strong style="color:var(--err)">-'+r.kevs+'</strong> KEVs</span>':'')
        +badges
        +(kb?'<span style="font-size:.6rem;color:var(--p);font-weight:500">'+kb+'</span>':'')
        +'</div></div></div>';
    });
    html+='</div>';

    // ── What-If Simulator ──
    html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px">'
      +'<h3 style="font-family:var(--fd);font-size:.88rem;font-weight:600;margin-bottom:14px;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:20px;color:#7c3aed">science</span>Simulador What-If</h3>'
      +'<div style="font-size:.68rem;color:var(--t2);margin-bottom:14px">Selecciona parches para simular su impacto en el riesgo global</div>';

    // Checkboxes for top patches
    html+='<div id="whatifChecks" style="display:flex;flex-direction:column;gap:4px;max-height:180px;overflow-y:auto;margin-bottom:14px">';
    recSorted.forEach(function(r, i){
      html+='<label style="display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:8px;cursor:pointer;font-size:.72rem;transition:background .15s" onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'">'
        +'<input type="checkbox" data-hosts="'+r.hosts.size+'" data-kevs="'+r.kevs+'" data-name="'+r.name.substring(0,40).replace(/"/g,"&quot;")+'" style="accent-color:#7c3aed;width:15px;height:15px" onchange="window._whatifCalc()">'
        +'<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+r.name.substring(0,45)+(r.name.length>45?'...':'')+'</span>'
        +'<span style="font-family:var(--fd);font-weight:600;font-size:.68rem;color:var(--p);flex-shrink:0">'+r.hosts.size+' hosts</span>'
        +'</label>';
    });
    html+='</div>';

    // Result area
    html+='<div id="whatifResult" style="background:var(--s2);border-radius:12px;padding:16px;text-align:center">'
      +'<div style="font-size:.72rem;color:var(--t2);margin-bottom:8px">Selecciona parches arriba para simular</div>'
      +'<div style="display:flex;align-items:center;gap:12px;justify-content:center">'
      +'<div style="text-align:center"><div style="width:52px;height:52px;border-radius:50%;border:3px solid var(--warn);display:grid;place-items:center;font-family:var(--fd);font-weight:700;font-size:1.1rem;color:var(--warn)" id="whatifFrom">'+riskScore+'</div><div style="font-size:.55rem;color:var(--t2);margin-top:2px">Actual</div></div>'
      +'<span class="material-icons-round" style="font-size:24px;color:var(--t2)">arrow_forward</span>'
      +'<div style="text-align:center"><div style="width:52px;height:52px;border-radius:50%;border:3px solid var(--ok);display:grid;place-items:center;font-family:var(--fd);font-weight:700;font-size:1.1rem;color:var(--ok)" id="whatifTo">'+riskScore+'</div><div style="font-size:.55rem;color:var(--t2);margin-top:2px">Proyectado</div></div>'
      +'<div style="text-align:center;margin-left:8px" id="whatifDelta"><div style="font-family:var(--fd);font-weight:700;font-size:1.3rem;color:var(--t2)">0</div><div style="font-size:.55rem;color:var(--t2)">Reducción</div></div>'
      +'</div>'
      +'<div id="whatifDetail" style="margin-top:10px;font-size:.65rem;color:var(--t2)"></div>'
      +'</div>';

    html+='</div>';
    html+='</div>'; // end row 4

    // ═══ ROW 5: TREND CHART (if multiple snapshots) ═══
    if(snaps.length >= 2){
      html+='<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:20px;margin-bottom:18px">'
        +'<h3 style="font-family:var(--fd);font-size:.88rem;font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:20px;color:var(--p)">show_chart</span>Tendencia de Riesgo</h3>'
        +'<div style="font-size:.68rem;color:var(--t2);margin-bottom:16px">Evolución basada en '+snaps.length+' snapshots cargados</div>';

      // Build SVG line chart
      var cW = 700, cH = 200, pad = 40;
      var maxV = Math.max.apply(null, trendValues) || 1;
      var maxH = Math.max.apply(null, trendHosts) || 1;

      html+='<div style="width:100%;overflow-x:auto">';
      html+='<svg viewBox="0 0 '+(cW+pad*2)+' '+(cH+pad*2)+'" style="width:100%;max-width:800px;height:auto;display:block;margin:0 auto">';

      // Grid lines
      for(var gi=0; gi<=4; gi++){
        var gy = pad + (cH/4)*gi;
        var gVal = Math.round(maxV - (maxV/4)*gi);
        html+='<line x1="'+pad+'" y1="'+gy+'" x2="'+(cW+pad)+'" y2="'+gy+'" stroke="var(--olv)" stroke-width="1" stroke-dasharray="4"/>';
        html+='<text x="'+(pad-6)+'" y="'+(gy+4)+'" text-anchor="end" font-size="9" fill="var(--t2)" font-family="var(--fd)">'+gVal+'</text>';
      }

      // Vulns line
      var vPts = trendValues.map(function(v, i){
        var x = pad + (i/(trendValues.length-1))*cW;
        var y = pad + (1 - v/maxV)*cH;
        return x+','+y;
      });
      // Area fill
      html+='<polygon points="'+vPts.join(' ')+' '+(pad+cW)+','+(pad+cH)+' '+pad+','+(pad+cH)+'" fill="var(--err)" opacity=".08"/>';
      html+='<polyline points="'+vPts.join(' ')+'" fill="none" stroke="var(--err)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>';

      // Hosts line
      var hPts = trendHosts.map(function(v, i){
        var x = pad + (i/(trendHosts.length-1))*cW;
        var y = pad + (1 - v/maxH)*cH;
        return x+','+y;
      });
      html+='<polyline points="'+hPts.join(' ')+'" fill="none" stroke="var(--p)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="6,3"/>';

      // Data points + labels
      trendValues.forEach(function(v, i){
        var x = pad + (i/(trendValues.length-1))*cW;
        var y = pad + (1 - v/maxV)*cH;
        html+='<circle cx="'+x+'" cy="'+y+'" r="4" fill="var(--err)" stroke="var(--s1)" stroke-width="2"/>';
        // Date label on x-axis
        var snapName = snaps[i] ? snaps[i].name : '';
        var dateMatch = snapName.match(/(\d{8})/);
        var dateLabel = dateMatch ? dateMatch[1].substring(4,6)+'/'+dateMatch[1].substring(6,8) : (i+1);
        html+='<text x="'+x+'" y="'+(pad+cH+16)+'" text-anchor="middle" font-size="8" fill="var(--t2)" font-family="var(--fd)">'+dateLabel+'</text>';
      });

      // Axes
      html+='<line x1="'+pad+'" y1="'+pad+'" x2="'+pad+'" y2="'+(pad+cH)+'" stroke="var(--ol)" stroke-width="1"/>';
      html+='<line x1="'+pad+'" y1="'+(pad+cH)+'" x2="'+(pad+cW)+'" y2="'+(pad+cH)+'" stroke="var(--ol)" stroke-width="1"/>';

      html+='</svg></div>';

      // Legend
      html+='<div style="display:flex;gap:16px;justify-content:center;margin-top:10px;font-size:.7rem;color:var(--t2)">'
        +'<span style="display:flex;align-items:center;gap:5px"><span style="width:16px;height:3px;background:var(--err);border-radius:2px;display:inline-block"></span> Vulnerabilidades</span>'
        +'<span style="display:flex;align-items:center;gap:5px"><span style="width:16px;height:3px;background:var(--p);border-radius:2px;display:inline-block;border-top:1px dashed var(--p)"></span> Hosts afectados</span>'
        +'</div>';

      // Delta summary
      var firstV = trendValues[0], lastV = trendValues[trendValues.length-1];
      var deltaV = lastV - firstV;
      var deltaColor = deltaV > 0 ? 'var(--err)' : deltaV < 0 ? 'var(--ok)' : 'var(--t2)';
      var deltaIcon = deltaV > 0 ? 'trending_up' : deltaV < 0 ? 'trending_down' : 'trending_flat';
      html+='<div style="display:flex;gap:14px;justify-content:center;margin-top:12px;flex-wrap:wrap">';
      html+='<div style="background:var(--s2);border-radius:10px;padding:8px 16px;text-align:center"><div style="font-size:.58rem;color:var(--t2);text-transform:uppercase">Primer scan</div><div style="font-family:var(--fd);font-weight:700;font-size:1rem">'+firstV.toLocaleString()+'</div></div>';
      html+='<div style="background:var(--s2);border-radius:10px;padding:8px 16px;text-align:center"><div style="font-size:.58rem;color:var(--t2);text-transform:uppercase">Último scan</div><div style="font-family:var(--fd);font-weight:700;font-size:1rem">'+lastV.toLocaleString()+'</div></div>';
      html+='<div style="background:var(--s2);border-radius:10px;padding:8px 16px;text-align:center"><div style="font-size:.58rem;color:var(--t2);text-transform:uppercase">Variación</div><div style="font-family:var(--fd);font-weight:700;font-size:1rem;color:'+deltaColor+';display:flex;align-items:center;gap:4px"><span class="material-icons-round" style="font-size:16px">'+deltaIcon+'</span>'+(deltaV>0?'+':'')+deltaV.toLocaleString()+'</div></div>';
      html+='</div>';

      html+='</div>';
    }

    html+='</div>';
    ct.innerHTML = html;
  };

  // What-If calculator
  window._whatifCalc = function(){
    var checks = document.querySelectorAll('#whatifChecks input[type=checkbox]:checked');
    var totalHostsReduced = 0, totalKevs = 0, names = [];
    checks.forEach(function(c){
      totalHostsReduced += parseInt(c.dataset.hosts)||0;
      totalKevs += parseInt(c.dataset.kevs)||0;
      names.push(c.dataset.name);
    });

    var raw = window._raw; if(!raw) return;
    var totalHosts = new Set(); raw.forEach(function(r){ totalHosts.add(r.hostname); });
    var th = totalHosts.size;

    // Recalc risk with selected patches removed
    var currentRisk = parseInt(document.getElementById('whatifFrom').textContent)||0;
    var reductionPct = th > 0 ? totalHostsReduced / th : 0;
    var kevReduction = totalKevs > 0 ? 0.15 : 0;
    var newRisk = Math.max(Math.round(currentRisk * (1 - reductionPct * 0.8 - kevReduction)), 0);

    var fromEl = document.getElementById('whatifFrom');
    var toEl = document.getElementById('whatifTo');
    var deltaEl = document.getElementById('whatifDelta');
    var detailEl = document.getElementById('whatifDetail');

    if(checks.length === 0){
      toEl.textContent = currentRisk;
      toEl.style.color = 'var(--warn)';
      toEl.style.borderColor = 'var(--warn)';
      deltaEl.querySelector('div').textContent = '0';
      deltaEl.querySelector('div').style.color = 'var(--t2)';
      detailEl.innerHTML = '';
      return;
    }

    var reduction = currentRisk - newRisk;
    var toColor = newRisk >= 700 ? 'var(--err)' : newRisk >= 300 ? 'var(--warn)' : 'var(--ok)';

    toEl.textContent = newRisk;
    toEl.style.color = toColor;
    toEl.style.borderColor = toColor;
    deltaEl.querySelector('div').textContent = '-' + reduction;
    deltaEl.querySelector('div').style.color = 'var(--ok)';
    detailEl.innerHTML = '<strong style="color:var(--ok)">' + checks.length + ' parche'+(checks.length>1?'s':'')+'</strong> seleccionado'+(checks.length>1?'s':'')
      +' · <strong>' + totalHostsReduced + '</strong> hosts impactados'
      +(totalKevs > 0 ? ' · <strong style="color:var(--err)">' + totalKevs + '</strong> KEVs eliminados' : '')
      +' · Reducción estimada: <strong style="color:var(--ok)">' + Math.round(reductionPct*100) + '%</strong>';
  };
})();
