// INFORME — Dossier ejecutivo + técnico generado con IA (Gemini)
// Tono mixto CISO/técnico · Español · Export DOCX con gráficos embebidos
(function(){

  var _state = { ctx:null, sections:null, markdown:null };

  // ══════════════════════════════════════════════════════════════════════════
  // 1) CONTEXTO DETERMINISTA — los números los pone el código, no la IA
  // ══════════════════════════════════════════════════════════════════════════
  function buildReportContext(){
    var raw = window._raw; if(!raw||!raw.length) return null;
    var snaps = window._snapshots||[];
    var idx = window._currentFileIndex||0;
    var snap = snaps[idx]||null;
    var snapPrev = idx>0 ? snaps[idx-1] : null;
    var totalDevices = window.totalDevices||0;

    function uniqHosts(filter){
      var s = new Set();
      raw.forEach(function(r){ if(filter(r)&&r.hostname) s.add(r.hostname); });
      return s.size;
    }
    function uniqHostList(filter, max){
      var s = new Set();
      raw.forEach(function(r){ if(filter(r)&&r.hostname) s.add(r.hostname); });
      return [...s].slice(0, max||10);
    }

    var tH = uniqHosts(function(){ return true; });
    var tV = raw.length;
    var hab = uniqHosts(function(r){ return r.estadoAD==='HABILITADO'; });
    var des = uniqHosts(function(r){ return r.estadoAD==='DESHABILITADO'; });
    var crit = uniqHosts(function(r){ return r.estadoAD==='HABILITADO'&&r.diasQualys>15&&r.diasLogon>15; });
    var fantasmas = uniqHosts(function(r){ return r.estadoAD==='DESHABILITADO'; });
    var abandonados = uniqHosts(function(r){ return r.estadoAD==='HABILITADO'&&r.diasLogon>90; });

    // Severidad
    var sev = {Critical:0,High:0,Medium:0,Low:0};
    raw.forEach(function(r){
      var s = (r.nivelVPR||'').toLowerCase();
      var n = parseFloat((s.match(/\d+\.?\d*/)||[null])[0]);
      if(s.indexOf('critic')>=0||(n!=null&&n>=9)) sev.Critical++;
      else if(s.indexOf('high')>=0||(n!=null&&n>=7)) sev.High++;
      else if(s.indexOf('med')>=0||(n!=null&&n>=4)) sev.Medium++;
      else sev.Low++;
    });

    // KEV
    var kevOK = !!(window._kevStatus&&window._kevStatus.ok);
    var kevVulnSet = new Set(), kevHostSet = new Set();
    raw.forEach(function(r){
      if(r.isKEV){
        if(r.vulnName) kevVulnSet.add(r.vulnName);
        if(r.hostname) kevHostSet.add(r.hostname);
      }
    });

    // Top vulnerabilidades
    var vulnMap = {};
    raw.forEach(function(r){
      if(!r.vulnName) return;
      if(!vulnMap[r.vulnName]) vulnMap[r.vulnName] = { hosts:new Set(), cves:new Set(), kev:false, vpr:r.nivelVPR||'-' };
      vulnMap[r.vulnName].hosts.add(r.hostname);
      if(r.cves) (''+r.cves).split('|').map(function(c){return c.trim();}).filter(Boolean).forEach(function(c){ vulnMap[r.vulnName].cves.add(c); });
      if(r.isKEV) vulnMap[r.vulnName].kev = true;
    });
    var topVulns = Object.keys(vulnMap).map(function(name){
      var v = vulnMap[name];
      return {
        name: name.length>110?name.substring(0,108)+'…':name,
        hosts: v.hosts.size,
        cves: [...v.cves].slice(0,5),
        kev: v.kev,
        vpr: v.vpr
      };
    }).sort(function(a,b){ return b.hosts-a.hosts; }).slice(0,10);

    // Por entorno
    var envMap = {};
    raw.forEach(function(r){
      var e = r.entorno||'Sin clasificar';
      if(!envMap[e]) envMap[e] = { hosts:new Set(), vulns:0, kev:0, crit:0 };
      envMap[e].hosts.add(r.hostname);
      envMap[e].vulns++;
      if(r.isKEV) envMap[e].kev++;
      if(r.estadoAD==='HABILITADO'&&r.diasQualys>15&&r.diasLogon>15) envMap[e].crit++;
    });
    var environments = Object.keys(envMap).map(function(e){
      return { name:e, hosts:envMap[e].hosts.size, vulns:envMap[e].vulns, kev:envMap[e].kev, crit:envMap[e].crit };
    }).sort(function(a,b){ return b.hosts-a.hosts; });

    // Por torre (equipo responsable)
    var torreMap = {};
    raw.forEach(function(r){
      var t = r.torre || 'Sin clasificar';
      if(!torreMap[t]) torreMap[t] = { hosts:new Set(), vulns:0, kev:0, crit:0 };
      torreMap[t].hosts.add(r.hostname);
      torreMap[t].vulns++;
      if(r.isKEV) torreMap[t].kev++;
      if(r.diasQualys>15) torreMap[t].crit++;
    });
    var towers = Object.keys(torreMap).map(function(t){
      return { name:t, hosts:torreMap[t].hosts.size, vulns:torreMap[t].vulns, kev:torreMap[t].kev, crit:torreMap[t].crit };
    }).sort(function(a,b){ return b.vulns-a.vulns; });

    // Antigüedad de escaneo Qualys (por host)
    var ageHist = {'0-7':0,'8-30':0,'31-60':0,'61-90':0,'90+':0};
    var perHost = {};
    raw.forEach(function(r){
      if(!r.hostname) return;
      if(perHost[r.hostname]==null) perHost[r.hostname] = r.diasQualys||0;
    });
    Object.keys(perHost).forEach(function(h){
      var d = perHost[h];
      if(d<=7) ageHist['0-7']++;
      else if(d<=30) ageHist['8-30']++;
      else if(d<=60) ageHist['31-60']++;
      else if(d<=90) ageHist['61-90']++;
      else ageHist['90+']++;
    });

    // Antigüedad media
    var avgQ = 0;
    var hostKeys = Object.keys(perHost);
    if(hostKeys.length>0){
      avgQ = Math.round(hostKeys.reduce(function(s,h){ return s+perHost[h]; },0)/hostKeys.length);
    }

    // SLA
    var slaData = null; try{ slaData = JSON.parse(localStorage.getItem('sla_thresholds_v1')||'null'); }catch(e){}
    var slaSummary = null;
    if(slaData){
      var slaOK=0, slaBreach=0;
      raw.forEach(function(r){
        var vpr = (r.nivelVPR||'');
        var lv = vpr.indexOf('9')>=0 ? 'critical' : (vpr.indexOf('7')>=0||vpr.indexOf('8')>=0) ? 'high' : 'medium';
        if((r.diasQualys||0) <= (slaData[lv]||90)) slaOK++; else slaBreach++;
      });
      slaSummary = {
        cumplimientoPct: tV>0 ? Math.round(slaOK/tV*100) : null,
        dentroDePlazo: slaOK,
        incumplimientos: slaBreach,
        umbrales: slaData
      };
    }

    // Tendencia
    var trend = null;
    if(snap && snapPrev){
      trend = {
        snapshotPrevio: snapPrev.name,
        snapshotActual: snap.name,
        deltaVulns: snap.totalV - snapPrev.totalV,
        deltaHosts: snap.totalH - snapPrev.totalH,
        deltaCriticos: (snap.crit||0) - (snapPrev.crit||0),
        deltaHabilitados: (snap.hab||0) - (snapPrev.hab||0)
      };
    }

    // Evolución para gráfico de línea
    var evolucion = snaps.map(function(s){
      return { name:s.name, vulns:s.totalV, hosts:s.totalH, crit:s.crit||0 };
    });

    return {
      meta: {
        fecha: new Date().toLocaleDateString('es-ES'),
        cliente: 'Cajamar',
        proveedor: 'DXC Technology',
        snapshot: snap?snap.name:'Datos actuales',
        snapshotsAnalizados: snaps.length
      },
      kpis: {
        parqueTotal: totalDevices,
        hostsConVulns: tH,
        coberturaPct: totalDevices>0 ? Math.round(tH/totalDevices*1000)/10 : null,
        totalVulns: tV,
        habilitados: hab,
        deshabilitados: des,
        criticos: crit,
        fantasmas: fantasmas,
        abandonados: abandonados,
        antiguedadMediaDias: avgQ
      },
      severidad: sev,
      sla: slaSummary,
      kev: {
        catalogoOK: kevOK,
        vulnsActivas: kevVulnSet.size,
        hostsAfectados: kevHostSet.size,
        listado: [...kevVulnSet].slice(0,12)
      },
      topVulnerabilidades: topVulns,
      porEntorno: environments,
      porTorre: towers,
      antiguedadEscaneo: ageHist,
      muestrasHosts: {
        criticos: uniqHostList(function(r){ return r.estadoAD==='HABILITADO'&&r.diasQualys>15&&r.diasLogon>15; }, 10),
        fantasmas: uniqHostList(function(r){ return r.estadoAD==='DESHABILITADO'; }, 8),
        abandonados: uniqHostList(function(r){ return r.estadoAD==='HABILITADO'&&r.diasLogon>90; }, 8)
      },
      tendencia: trend,
      evolucion: evolucion
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  // 2) MARKDOWN → HTML (preview en streaming)
  // ══════════════════════════════════════════════════════════════════════════
  function mdToHtml(md){
    if(!md) return '';
    function inline(t){
      t = t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      t = t.replace(/`([^`]+)`/g, '<code style="background:rgba(124,58,237,.1);color:#7c3aed;padding:1px 6px;border-radius:4px;font-family:Monaco,monospace;font-size:.88em">$1</code>');
      t = t.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
      t = t.replace(/(^|[^*])\*([^*\n]+)\*([^*]|$)/g, '$1<em>$2</em>$3');
      return t;
    }
    var lines = md.split('\n'), html='', inUl=false, paraBuf=[], ord=0;
    function closeUl(){ if(inUl){ html+='</ul>'; inUl=false; } }
    function flushPara(){ if(paraBuf.length>0){ html+='<p style="margin:8px 0;line-height:1.65">'+inline(paraBuf.join(' '))+'</p>'; paraBuf=[]; } }
    for(var i=0;i<lines.length;i++){
      var l = lines[i].replace(/\s+$/,'');
      if(!l){ flushPara(); closeUl(); continue; }
      if(/^##\s+/.test(l)){ flushPara(); closeUl(); ord=0; html+='<h2 style="font-family:var(--fd);font-size:1.05rem;font-weight:700;margin:22px 0 10px;color:var(--t);display:flex;align-items:center;gap:10px"><span style="width:4px;height:20px;background:#7c3aed;border-radius:2px;flex-shrink:0"></span>'+inline(l.replace(/^##\s+/,''))+'</h2>'; continue; }
      if(/^#\s+/.test(l)){ flushPara(); closeUl(); ord=0; html+='<h1 style="font-family:var(--fd);font-size:1.2rem;font-weight:700;margin:22px 0 12px">'+inline(l.replace(/^#\s+/,''))+'</h1>'; continue; }
      var ulm = l.match(/^[-*+]\s+(.+)$/);
      if(ulm){ flushPara(); if(!inUl){ html+='<ul style="margin:6px 0 10px 0;padding-left:22px">'; inUl=true; } html+='<li style="margin:4px 0;line-height:1.55">'+inline(ulm[1])+'</li>'; continue; }
      var olm = l.match(/^(\d+)\.\s+(.+)$/);
      if(olm){
        flushPara(); closeUl(); ord++;
        html+='<div style="display:flex;gap:12px;margin:10px 0;align-items:flex-start"><span style="flex-shrink:0;width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;display:grid;place-items:center;font-family:var(--fd);font-weight:700;font-size:.75rem;margin-top:1px">'+ord+'</span><div style="flex:1;line-height:1.6;padding-top:2px">'+inline(olm[2])+'</div></div>';
        continue;
      }
      closeUl();
      paraBuf.push(l);
    }
    flushPara(); closeUl();
    return html;
  }

  function parseSections(md){
    var out = {};
    if(!md) return out;
    var current = null, buf = [];
    md.split('\n').forEach(function(l){
      var m = l.match(/^##\s+(.+)$/);
      if(m){ if(current) out[current] = buf.join('\n').trim(); current = m[1].trim(); buf = []; }
      else { buf.push(l); }
    });
    if(current) out[current] = buf.join('\n').trim();
    return out;
  }

  // Construye preview enriquecido — IA narrativa + gráficos intercalados
  function buildSectionedPreviewHtml(sections, charts){
    var order = [
      'Resumen Ejecutivo',
      'Postura de Riesgo',
      'Exposición CISA KEV',
      'Top Vulnerabilidades por Impacto',
      'Análisis por Entorno',
      'Análisis por Torre',
      'Hosts Críticos y Equipos Fantasma',
      'Riesgos Emergentes',
      'Recomendaciones Operativas',
      'Conclusiones'
    ];
    // Gráficos a insertar DESPUÉS de cada sección (mismo orden que el DOCX)
    var chartsAfter = {
      'Postura de Riesgo': charts.tendencia ? [{key:'tendencia', caption:'Evolución de vulnerabilidades por snapshot'}] : [],
      'Top Vulnerabilidades por Impacto': [{key:'topVulns', caption:'Top 10 vulnerabilidades por equipos afectados'}],
      'Análisis por Entorno': [{key:'entornos', caption:'Equipos vulnerables por entorno'}],
      'Análisis por Torre': [{key:'torres', caption:'Vulnerabilidades por torre responsable'}],
      'Hosts Críticos y Equipos Fantasma': [{key:'antiguedad', caption:'Antigüedad del último escaneo Qualys (equipos)'}]
    };
    function img(dataUrl, caption){
      return '<figure style="margin:18px 0;text-align:center">'
        +'<img src="'+dataUrl+'" alt="'+(caption||'')+'" style="max-width:100%;height:auto;border:1px solid var(--olv);border-radius:10px;box-shadow:var(--e1);background:#fff"/>'
        +(caption?'<figcaption style="font-size:.68rem;color:var(--t2);margin-top:8px;font-style:italic">'+caption+'</figcaption>':'')
        +'</figure>';
    }
    var html = '';
    // Donut de severidad arriba como snapshot visual
    if(charts.severidad){
      html += img(charts.severidad, 'Distribución de vulnerabilidades por severidad');
    }
    order.forEach(function(name){
      var body = sections[name];
      if(!body) return;
      html += '<h2 style="font-family:var(--fd);font-size:1.05rem;font-weight:700;margin:24px 0 12px;color:var(--t);display:flex;align-items:center;gap:10px"><span style="width:4px;height:20px;background:#7c3aed;border-radius:2px;flex-shrink:0"></span>'+name+'</h2>';
      html += mdToHtml(body);
      (chartsAfter[name]||[]).forEach(function(c){
        if(charts[c.key]) html += img(charts[c.key], c.caption);
      });
    });
    return html;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // 3) GRÁFICOS — canvas → PNG dataURL para embeber en preview y DOCX
  // ══════════════════════════════════════════════════════════════════════════
  function makeCanvas(w,h){
    var c = document.createElement('canvas');
    c.width = w; c.height = h;
    return c;
  }

  function drawDonut(canvas, items, colors, title){
    var ctx = canvas.getContext('2d');
    var W = canvas.width, H = canvas.height;
    ctx.fillStyle = '#fff'; ctx.fillRect(0,0,W,H);
    if(title){
      ctx.fillStyle = '#202124';
      ctx.font = 'bold 18px sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(title, 20, 28);
    }
    var topY = title?44:12;
    var R = Math.min((H-topY-20)/2, 130);
    var cx = R+30, cy = topY + R + 4;
    var r = R*0.55;
    var total = items.reduce(function(s,i){ return s+i.value; },0)||1;
    var start = -Math.PI/2;
    items.forEach(function(it,i){
      if(it.value<=0) return;
      var ang = (it.value/total)*Math.PI*2;
      ctx.beginPath();
      ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,R,start,start+ang);
      ctx.closePath();
      ctx.fillStyle = colors[i%colors.length];
      ctx.fill();
      start += ang;
    });
    ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2);
    ctx.fillStyle = '#fff'; ctx.fill();
    ctx.fillStyle = '#202124';
    ctx.font = 'bold 26px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(total, cx, cy+8);
    ctx.font = '11px sans-serif';
    ctx.fillStyle = '#5f6368';
    ctx.fillText('total', cx, cy+24);
    // Legend
    var lx = cx + R + 30, ly = cy - (items.length*24)/2;
    ctx.font = '14px sans-serif';
    ctx.textAlign = 'left';
    items.forEach(function(it,i){
      ctx.fillStyle = colors[i%colors.length];
      ctx.fillRect(lx, ly+i*24-10, 14, 14);
      ctx.fillStyle = '#202124';
      var pct = total>0 ? Math.round(it.value/total*100) : 0;
      ctx.fillText(it.label+': '+it.value+' ('+pct+'%)', lx+22, ly+i*24+1);
    });
    return canvas.toDataURL('image/png');
  }

  function drawHBars(canvas, items, color, title){
    var ctx = canvas.getContext('2d');
    var W = canvas.width, H = canvas.height;
    ctx.fillStyle = '#fff'; ctx.fillRect(0,0,W,H);
    if(title){
      ctx.fillStyle = '#202124';
      ctx.font = 'bold 18px sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(title, 20, 28);
    }
    var topY = title?52:16;
    var pad = 16;
    var labelW = 280;
    var maxV = items.reduce(function(m,i){ return Math.max(m,i.value); },0)||1;
    var barH = (H - topY - pad) / Math.max(items.length,1) - 6;
    barH = Math.min(barH, 30);
    items.forEach(function(it,i){
      var y = topY + i*(barH+6);
      ctx.fillStyle = '#5f6368';
      ctx.font = '13px sans-serif';
      ctx.textAlign = 'left';
      var lbl = it.label.length>40 ? it.label.substring(0,38)+'…' : it.label;
      ctx.fillText(lbl, pad, y+barH/2+5);
      var bx = pad + labelW;
      var availableW = W - bx - pad - 70;
      var bw = (it.value/maxV) * availableW;
      // Rounded rect bar
      ctx.fillStyle = color;
      ctx.fillRect(bx, y, bw, barH);
      // Value
      ctx.fillStyle = '#202124';
      ctx.font = 'bold 13px sans-serif';
      ctx.fillText(it.value, bx+bw+8, y+barH/2+5);
    });
    return canvas.toDataURL('image/png');
  }

  function drawLine(canvas, points, title, color){
    color = color || '#1a73e8';
    var ctx = canvas.getContext('2d');
    var W = canvas.width, H = canvas.height;
    ctx.fillStyle = '#fff'; ctx.fillRect(0,0,W,H);
    if(title){
      ctx.fillStyle = '#202124';
      ctx.font = 'bold 18px sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(title, 20, 28);
    }
    if(points.length<2){
      ctx.fillStyle = '#5f6368';
      ctx.font = '14px sans-serif';
      ctx.fillText('Datos insuficientes para mostrar tendencia', 20, 60);
      return canvas.toDataURL('image/png');
    }
    var padL = 60, padR = 30, padT = title?52:24, padB = 50;
    var plotW = W - padL - padR, plotH = H - padT - padB;
    var maxV = Math.max.apply(null, points.map(function(p){ return p.v; }));
    var minV = Math.min.apply(null, points.map(function(p){ return p.v; }));
    var range = maxV - minV || maxV || 1;
    // Padding to range
    var plotMax = maxV + range*0.1;
    var plotMin = Math.max(0, minV - range*0.1);
    var plotRange = plotMax - plotMin || 1;
    // Grid lines
    ctx.strokeStyle = '#e8eaed';
    ctx.lineWidth = 1;
    for(var g=0; g<=4; g++){
      var gy = padT + g*(plotH/4);
      ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(W-padR, gy); ctx.stroke();
      ctx.fillStyle = '#5f6368';
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'right';
      var v = Math.round(plotMax - g*(plotRange/4));
      ctx.fillText(v, padL-6, gy+4);
    }
    // Line
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    points.forEach(function(p,i){
      var x = padL + (i/(points.length-1))*plotW;
      var y = padT + ((plotMax - p.v)/plotRange)*plotH;
      if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    });
    ctx.stroke();
    // Points + value labels
    points.forEach(function(p,i){
      var x = padL + (i/(points.length-1))*plotW;
      var y = padT + ((plotMax - p.v)/plotRange)*plotH;
      ctx.beginPath(); ctx.arc(x,y,5,0,Math.PI*2);
      ctx.fillStyle = color; ctx.fill();
      ctx.fillStyle = '#fff'; ctx.beginPath(); ctx.arc(x,y,2.5,0,Math.PI*2); ctx.fill();
      ctx.fillStyle = '#202124';
      ctx.font = 'bold 12px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(p.v, x, y-12);
      // x label
      ctx.fillStyle = '#5f6368';
      ctx.font = '10px sans-serif';
      var lbl = (p.label||'').length>14 ? p.label.substring(0,12)+'…' : (p.label||'');
      ctx.fillText(lbl, x, H-padB+18);
    });
    return canvas.toDataURL('image/png');
  }

  function generateReportCharts(ctx){
    var charts = {};
    var sev = ctx.severidad;
    charts.severidad = drawDonut(makeCanvas(720,300),
      [
        {label:'Crítica', value:sev.Critical},
        {label:'Alta',    value:sev.High},
        {label:'Media',   value:sev.Medium},
        {label:'Baja',    value:sev.Low}
      ],
      ['#d93025', '#f9ab00', '#1a73e8', '#188038'],
      'Distribución por severidad'
    );

    charts.topVulns = drawHBars(makeCanvas(900,460),
      ctx.topVulnerabilidades.map(function(v){ return {label:v.name, value:v.hosts}; }),
      '#d93025',
      'Top 10 vulnerabilidades por equipos afectados'
    );

    charts.entornos = drawHBars(makeCanvas(900, Math.max(220, 80+ctx.porEntorno.length*42)),
      ctx.porEntorno.map(function(e){ return {label:e.name, value:e.hosts}; }),
      '#1a73e8',
      'Equipos vulnerables por entorno'
    );

    if(ctx.porTorre && ctx.porTorre.length){
      charts.torres = drawHBars(makeCanvas(900, Math.max(220, 80+ctx.porTorre.length*42)),
        ctx.porTorre.map(function(t){ return {label:t.name, value:t.vulns}; }),
        '#7c3aed',
        'Vulnerabilidades por torre responsable'
      );
    }

    charts.antiguedad = drawHBars(makeCanvas(800, 280),
      Object.keys(ctx.antiguedadEscaneo).map(function(k){ return {label:k+' días', value:ctx.antiguedadEscaneo[k]}; }),
      '#f9ab00',
      'Antigüedad del último escaneo Qualys (equipos)'
    );

    if(ctx.evolucion && ctx.evolucion.length>=2){
      charts.tendencia = drawLine(makeCanvas(900, 320),
        ctx.evolucion.map(function(s){ return {label:s.name, v:s.vulns}; }),
        'Evolución de vulnerabilidades por snapshot'
      );
    }
    return charts;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // 4) RENDER PANEL
  // ══════════════════════════════════════════════════════════════════════════
  window.renderInfPanel = function(){
    var ct = document.getElementById('ct-inf'); if(!ct) return;
    var raw = window._raw;
    if(!raw||!raw.length){
      ct.innerHTML = '<div style="text-align:center;padding:60px;color:var(--t2)"><span class="material-icons-round" style="font-size:48px;display:block;opacity:.3;margin-bottom:12px">summarize</span>Carga un CSV primero</div>';
      return;
    }

    _state.ctx = buildReportContext();
    _state.sections = null;
    _state.markdown = null;
    var ctx = _state.ctx;

    var html = '<div class="inf-panel">';

    // Header
    html += '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:24px">'
      +'<div style="display:flex;align-items:center;gap:14px">'
      +'<div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;box-shadow:0 4px 14px rgba(124,58,237,.3)"><span class="material-icons-round" style="font-size:28px;color:#fff">summarize</span></div>'
      +'<div><div style="font-family:var(--fd);font-size:1.2rem;font-weight:700;letter-spacing:-.3px;display:flex;align-items:center;gap:8px">Informe Ejecutivo<span style="background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-size:.55rem;padding:2px 8px;border-radius:10px;font-weight:700;letter-spacing:.5px">GEMINI IA</span></div>'
      +'<div style="font-size:.73rem;color:var(--t2);margin-top:3px">Dossier ejecutivo + técnico generado con IA · '+ctx.meta.proveedor+' para '+ctx.meta.cliente+' · '+ctx.meta.fecha+'</div></div>'
      +'</div>'
      +'<button onclick="window._geminiOpenKeyModal()" title="Configurar API Key" style="display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:22px;border:1.5px solid var(--ol);background:var(--s1);color:var(--t2);cursor:pointer;font-family:var(--fd);font-size:.72rem;font-weight:500" onmouseover="this.style.borderColor=\'#7c3aed\';this.style.color=\'#7c3aed\'" onmouseout="this.style.borderColor=\'var(--ol)\';this.style.color=\'var(--t2)\'"><span class="material-icons-round" style="font-size:14px">key</span>API Key</button>'
      +'</div>';

    // KPI summary cards (deterministic — los números siempre son los mismos)
    var kpis = [
      ['Parque total',           ctx.kpis.parqueTotal,                 'devices',       'var(--p)'],
      ['Equipos vulnerables',    ctx.kpis.hostsConVulns+(ctx.kpis.coberturaPct!=null?' ('+ctx.kpis.coberturaPct+'%)':''),'bug_report','var(--err)'],
      ['Vulnerabilidades',       ctx.kpis.totalVulns.toLocaleString(),'warning',       'var(--warn)'],
      ['Críticos (Q+AD >15d)',   ctx.kpis.criticos,                    'priority_high', 'var(--err)'],
      ['CISA KEV activas',       ctx.kev.vulnsActivas,                 'shield',        '#7c3aed'],
      ['Antigüedad media',       ctx.kpis.antiguedadMediaDias+'d',     'event_busy',    'var(--warn)']
    ];
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:22px">';
    kpis.forEach(function(k){
      html += '<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);padding:14px 16px">'
        +'<div style="display:flex;align-items:center;gap:6px;font-size:.58rem;text-transform:uppercase;letter-spacing:.5px;color:var(--t2);font-weight:600;margin-bottom:6px"><span class="material-icons-round" style="font-size:13px;color:'+k[3]+'">'+k[2]+'</span>'+k[0]+'</div>'
        +'<div style="font-family:var(--fd);font-size:1.5rem;font-weight:700;color:'+k[3]+';letter-spacing:-.3px">'+k[1]+'</div>'
        +'</div>';
    });
    html += '</div>';

    // Generate area
    html += '<div id="infGenArea">';
    html += '<div style="text-align:center;padding:48px 24px;background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);margin-bottom:16px;border:2px dashed rgba(124,58,237,.22)">'
      +'<div style="width:64px;height:64px;border-radius:18px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;margin:0 auto 16px;box-shadow:0 6px 20px rgba(124,58,237,.35)"><span class="material-icons-round" style="font-size:32px;color:#fff">auto_awesome</span></div>'
      +'<div style="font-family:var(--fd);font-size:1.1rem;font-weight:700;margin-bottom:6px">Generar Informe Ejecutivo con IA</div>'
      +'<div style="font-size:.78rem;color:var(--t2);margin-bottom:20px;max-width:600px;margin-left:auto;margin-right:auto;line-height:1.55">Gemini analizará los <strong>'+ctx.kpis.totalVulns.toLocaleString()+' hallazgos</strong> de <strong>'+ctx.kpis.hostsConVulns+' equipos</strong> y producirá un dossier completo en español: resumen ejecutivo, postura de riesgo, exposición CISA KEV, top vulnerabilidades, análisis por entorno, hosts críticos, riesgos emergentes, recomendaciones operativas y conclusiones.</div>'
      +'<button onclick="window._infGenerate()" style="display:inline-flex;align-items:center;gap:10px;padding:14px 32px;border-radius:30px;border:none;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-family:var(--fd);font-size:.92rem;font-weight:600;cursor:pointer;box-shadow:0 4px 18px rgba(124,58,237,.35);transition:all .2s" onmouseover="this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'0 6px 24px rgba(124,58,237,.45)\'" onmouseout="this.style.transform=\'none\';this.style.boxShadow=\'0 4px 18px rgba(124,58,237,.35)\'">'
      +'<span class="material-icons-round" style="font-size:22px">auto_awesome</span>Generar Informe con IA</button>'
      +'<div style="margin-top:14px;font-size:.65rem;color:var(--t2)">Modelo: '+(window._geminiActiveModel||'gemini-3-flash-preview')+' · El export Word incluye gráficos (severidad, top vulns, entornos, antigüedad, tendencia)</div>'
      +'</div>';
    html += '</div>';

    html += '</div>';
    ct.innerHTML = html;
  };

  // ══════════════════════════════════════════════════════════════════════════
  // 5) GENERACIÓN IA — streaming Gemini
  // ══════════════════════════════════════════════════════════════════════════
  window._infGenerate = function(){
    if(!window._geminiHasKey || !window._geminiHasKey()){
      window._geminiOpenKeyModal(function(){ window._infGenerate(); });
      return;
    }
    var area = document.getElementById('infGenArea'); if(!area) return;
    var ctx = _state.ctx; if(!ctx){ _state.ctx = buildReportContext(); ctx = _state.ctx; }
    if(!ctx) return;

    if(!document.getElementById('streamBlinkStyle')){
      var style = document.createElement('style');
      style.id = 'streamBlinkStyle';
      style.textContent = '@keyframes streamBlink{0%,49%{opacity:1}50%,100%{opacity:0}}.md-cursor{display:inline-block;width:8px;height:1.1em;background:#7c3aed;vertical-align:-2px;margin-left:2px;animation:streamBlink 1s steps(1) infinite;border-radius:2px}';
      document.head.appendChild(style);
    }

    area.innerHTML = '<div style="background:var(--s1);border-radius:var(--r);box-shadow:var(--e1);overflow:hidden;border-left:4px solid #7c3aed;margin-bottom:16px">'
      +'<div style="padding:16px 22px;border-bottom:1px solid var(--olv);display:flex;align-items:center;gap:14px">'
      +'<div style="width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;flex-shrink:0"><span class="material-icons-round" style="font-size:20px;color:#fff;animation:spin 1.5s linear infinite" id="infPhaseIcon">auto_awesome</span></div>'
      +'<div style="flex:1"><div style="font-family:var(--fd);font-weight:700;font-size:.95rem">Generando informe con Gemini</div><div id="infStatus" style="font-size:.7rem;color:var(--t2);margin-top:3px">Iniciando conexión con Gemini…</div></div>'
      +'<div id="infCounter" style="font-family:Monaco,monospace;font-size:.65rem;color:var(--t2);background:var(--s2);padding:4px 10px;border-radius:10px">0 tok</div>'
      +'</div>'
      +'<div id="infMd" style="padding:24px 30px;font-size:.85rem;color:var(--t);min-height:200px;line-height:1.65"></div>'
      +'</div>';

    var systemPrompt = 'Eres un consultor sénior de ciberseguridad de DXC Technology preparando un informe ejecutivo de gestión de vulnerabilidades para el banco Cajamar. '
      +'TONO: mixto ejecutivo + técnico. El destinatario es el CISO de Cajamar y su equipo de seguridad. Necesita visión estratégica clara, pero también detalle accionable (CVEs, hostnames, métricas concretas). '
      +'IDIOMA: español de España, profesional. '
      +'FORMATO: markdown limpio. Usa listas con guiones para enumeraciones y listas numeradas (1., 2., 3.) para acciones priorizadas. NO uses tablas markdown, NO uses HTML. '
      +'ESTILO: razonas como un consultor sénior, no enumeras datos: los interpretas. Sé concreto y específico — usa los números reales del contexto JSON. '
      +'INTEGRIDAD: NO inventes datos que no estén en el contexto JSON. Cíñete a los hechos. Si un dato no está, no lo menciones. '
      +'EXTENSIÓN: cada sección debe ser sustancial (3-6 párrafos o listas equivalentes). Es un informe completo, no un resumen.';

    var hasTrend = !!ctx.tendencia;
    var hasSLA = !!ctx.sla;
    var hasKEV = ctx.kev.vulnsActivas > 0;

    var userPrompt = 'Genera un INFORME EJECUTIVO COMPLETO de gestión de vulnerabilidades para Cajamar. Estructura EXACTAMENTE con estos encabezados ## en este orden:\n\n'
      +'## Resumen Ejecutivo\n'
      +'Párrafo único de 4-6 frases dirigido al CISO. Incluye obligatoriamente: número de equipos con vulnerabilidades sobre el parque total y porcentaje de cobertura, número de vulnerabilidades activas, hosts críticos, exposición a CISA KEV'+(hasTrend?', y la tendencia respecto al snapshot anterior':'')+'. Tono ejecutivo, claridad y contundencia.\n\n'
      +'## Postura de Riesgo\n'
      +'Análisis cualitativo del estado actual del parque (3-5 párrafos). Comenta: ratio de hosts críticos sobre el total, antigüedad media del último escaneo y qué implica, distribución de severidades (qué porcentaje son críticas/altas), '+(hasSLA?'cumplimiento del SLA actual y los incumplimientos detectados, ':'')+(hasTrend?'tendencia entre snapshots: si la situación mejora o empeora y la magnitud del cambio. ':'')+'Termina con una valoración cualitativa clara: ¿la postura es buena, aceptable, preocupante o crítica?\n\n'
      +'## Exposición CISA KEV\n'
      +(hasKEV
        ? 'Análisis del catálogo CISA KEV cruzado con el parque. Indica el número exacto de vulnerabilidades KEV activas y los hosts afectados. Lista las 5-7 más críticas con nombre completo y razona el riesgo de cada una. Explica por qué CISA las cataloga como "Known Exploited" y la urgencia de remediarlas en entornos bancarios sujetos a DORA.'
        : 'Comenta como aspecto positivo que NO se han detectado vulnerabilidades del catálogo CISA KEV en el parque actual. Explica brevemente qué es CISA KEV, por qué su ausencia es un buen indicador, y qué controles preventivos mantienen al parque limpio. Recomienda mantener la monitorización activa.'
      )+'\n\n'
      +'## Top Vulnerabilidades por Impacto\n'
      +'Comenta las 5-7 vulnerabilidades más impactantes del parque (las del top, ordenadas por hosts afectados). Por cada una expón: nombre exacto, número de hosts afectados, severidad VPR, si es CISA KEV (importante destacarlo), CVEs asociados si están disponibles, y una recomendación específica de remediación (parche, mitigación, priorización). No te limites a listar — interpreta el patrón global: ¿son todas del mismo vendor? ¿afectan al mismo tipo de equipo? ¿hay un denominador común explotable?\n\n'
      +'## Análisis por Entorno\n'
      +'Comenta cada entorno (PRO, PRE, DES o los que aparezcan) por separado. Por cada uno: número de hosts vulnerables, vulnerabilidades totales, KEV activos, hosts críticos, y qué implica para el negocio (PRO suele ser el más sensible). Identifica cuál es el entorno con mayor exposición relativa y propón decisiones priorizadas por entorno.\n\n'
      +'## Análisis por Torre\n'
      +'Comenta las 3-5 torres más afectadas del dato "porTorre" ordenado por nº de vulnerabilidades. Por cada torre indica: cuántas vulnerabilidades y hosts afecta, cuántas son KEV, el esfuerzo relativo que implica y la responsabilidad concreta del equipo (Wintel parchea servidores Windows, Device Management gestiona puestos/portátiles/cajeros, Citrix opera VDIs, Unix cubre servidores Linux/AIX, etc.). Propón un reparto claro de acciones entre las torres para la siguiente ventana de parcheo. Evita la torre "Sin clasificar" salvo que supere el 10%.\n\n'
      +'## Hosts Críticos y Equipos Fantasma\n'
      +'Tres categorías de hosts a vigilar:\n'
      +'- **Críticos activos**: hosts HABILITADOS en AD con escaneo Qualys >15 días Y login >15 días — máxima prioridad de remediación. Da el número y comenta el riesgo.\n'
      +'- **Equipos fantasma**: hosts DESHABILITADOS en AD que aún arrastran vulnerabilidades pendientes. Riesgo de re-habilitación o de servicios residuales.\n'
      +'- **Abandonados**: hosts HABILITADOS pero sin login >90 días. Riesgo de equipos olvidados sin parchear.\n'
      +'Para cada categoría: cifra, riesgo concreto y acción recomendada (decomisar, sacar de red, forzar parcheo, etc.).\n\n'
      +'## Riesgos Emergentes\n'
      +'Identifica 3-4 riesgos que pueden empeorar el SLA en próximas semanas si no se actúa: por ejemplo concentración de equipos sin escaneo reciente, '+(hasTrend?'aumento de vulnerabilidades respecto al snapshot anterior, ':'')+'crecimiento de KEVs, hosts críticos persistentes que no se han remediado, etc. Cada riesgo: descripción y por qué es crítico.\n\n'
      +'## Recomendaciones Operativas\n'
      +'Lista NUMERADA (1., 2., 3.…) de 6-8 acciones concretas y priorizadas. Cada acción debe incluir: descripción específica (no vaga), esfuerzo estimado (BAJO/MEDIO/ALTO), impacto esperado (en número de equipos saneados o reducción de riesgo), y plazo sugerido (días o semanas). Empieza por las que más reducen el SLA con menos esfuerzo (quick wins). Usa formato negrita para resaltar el verbo de acción inicial.\n\n'
      +'## Conclusiones\n'
      +'3-4 frases de cierre profesional dirigidas a Cajamar. Mensaje claro sobre la postura actual, el camino a seguir, y el compromiso de DXC con la mejora continua. Tono ejecutivo, sin tecnicismos.\n\n'
      +'CONTEXTO REAL DEL PARQUE (datos verídicos, cíñete a ellos):\n```json\n'+JSON.stringify(ctx, null, 2)+'\n```';

    var mdEl = document.getElementById('infMd');
    var statusEl = document.getElementById('infStatus');
    var countEl = document.getElementById('infCounter');
    function setStatus(t){ if(statusEl) statusEl.textContent = t; }

    window._geminiAskStream(userPrompt, systemPrompt, {
      temperature: 0.35,
      maxOutputTokens: 8192
    }, {
      onChunk: function(chunk, full){
        if(mdEl) mdEl.innerHTML = mdToHtml(full)+'<span class="md-cursor"></span>';
        if(countEl) countEl.textContent = Math.round(full.length/4).toLocaleString()+' tok';
        if(full.indexOf('## Conclusiones')>=0) setStatus('Cerrando conclusiones…');
        else if(full.indexOf('## Recomendaciones')>=0) setStatus('Generando recomendaciones operativas…');
        else if(full.indexOf('## Riesgos Emergentes')>=0) setStatus('Identificando riesgos emergentes…');
        else if(full.indexOf('## Hosts Críticos')>=0) setStatus('Analizando hosts críticos y fantasmas…');
        else if(full.indexOf('## Análisis por Entorno')>=0) setStatus('Analizando entornos…');
        else if(full.indexOf('## Top Vulnerabilidades')>=0) setStatus('Analizando top vulnerabilidades…');
        else if(full.indexOf('## Exposición CISA KEV')>=0) setStatus('Evaluando exposición CISA KEV…');
        else if(full.indexOf('## Postura de Riesgo')>=0) setStatus('Evaluando postura de riesgo…');
        else if(full.indexOf('## Resumen Ejecutivo')>=0) setStatus('Escribiendo resumen ejecutivo…');
        else setStatus('Gemini está analizando los datos…');
      },
      onDone: function(full){
        _state.markdown = full;
        _state.sections = parseSections(full);
        // Generar gráficos una sola vez — se reutilizan en el export DOCX
        try { _state.charts = generateReportCharts(_state.ctx); } catch(e){ _state.charts = {}; }
        if(mdEl) mdEl.innerHTML = buildSectionedPreviewHtml(_state.sections, _state.charts);
        var icon = document.getElementById('infPhaseIcon');
        if(icon){ icon.style.animation = 'none'; icon.textContent = 'check_circle'; }
        setStatus('Informe completo · Listo para exportar a Word');
        // Insert export buttons
        var existing = document.getElementById('infActionRow');
        if(existing) existing.remove();
        var row = document.createElement('div');
        row.id = 'infActionRow';
        row.style.cssText = 'display:flex;gap:12px;flex-wrap:wrap;justify-content:center;padding:16px 0';
        row.innerHTML = '<button class="inf-btn primary" onclick="window.exportInformeDocx()"><span class="material-icons-round">download</span> Exportar Word (.docx)</button>'
          +'<button class="inf-btn secondary" onclick="window._infGenerate()"><span class="material-icons-round">refresh</span> Regenerar</button>';
        document.getElementById('infGenArea').appendChild(row);
      },
      onError: function(e){
        var msg = e.message||'Error desconocido';
        if(msg==='NO_KEY'){
          window._geminiOpenKeyModal(function(){ window._infGenerate(); });
          return;
        }
        if(mdEl) mdEl.innerHTML = '<div style="padding:18px;background:var(--errc);border-radius:8px;color:var(--err)"><strong>Error:</strong> '+msg+'</div>';
        setStatus('Error al generar el informe');
      }
    });
  };

  // ══════════════════════════════════════════════════════════════════════════
  // 6) EXPORT DOCX — secciones IA + tablas + gráficos embebidos
  // ══════════════════════════════════════════════════════════════════════════
  window.exportInformeDocx = async function(){
    var ctx = _state.ctx;
    var sections = _state.sections || {};
    if(!ctx){ alert('Genera primero el informe con IA'); return; }
    var D = window.docx;
    if(!D){ alert('Librería docx no disponible'); return; }

    // Reusar los gráficos generados en el preview si ya existen
    var charts = _state.charts || generateReportCharts(ctx);

    function dataUrlToBytes(d){
      var b64 = d.split(',')[1];
      var bin = atob(b64);
      var arr = new Uint8Array(bin.length);
      for(var i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
      return arr;
    }

    function T(t,o){ o=o||{}; return new D.TextRun({text:t,font:'Calibri',size:o.size||22,bold:!!o.bold,color:o.color,italics:!!o.italics}); }
    function P(runs,o){ o=o||{}; return new D.Paragraph({children:Array.isArray(runs)?runs:[runs],spacing:{after:o.after||120,before:o.before||0},alignment:o.alignment}); }
    function H1(t){ return new D.Paragraph({children:[T(t,{bold:true,size:30,color:'1a73e8'})],heading:D.HeadingLevel.HEADING_1,spacing:{before:320,after:140},border:{bottom:{color:'1a73e8',space:4,size:8,style:D.BorderStyle.SINGLE}}}); }
    function bullet(t){ return new D.Paragraph({children:[T(t)],bullet:{level:0},spacing:{after:60}}); }
    function img(dataUrl, w, h){
      return new D.Paragraph({
        children:[new D.ImageRun({data:dataUrlToBytes(dataUrl),transformation:{width:w,height:h}})],
        alignment:D.AlignmentType.CENTER,
        spacing:{before:140,after:200}
      });
    }

    function stripMd(s){
      return s.replace(/\*\*(.+?)\*\*/g,'$1').replace(/`(.+?)`/g,'$1').replace(/\*(.+?)\*/g,'$1');
    }

    // Convertir bloque markdown → array de Paragraphs DOCX
    function mdBlock(md){
      if(!md){
        return [P([T('— sección sin contenido —',{italics:true,color:'5f6368'})])];
      }
      var paras = [], paraBuf = [], orderedCounter = 0;

      function inlineRuns(text){
        var runs = [];
        var parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/);
        parts.forEach(function(p){
          if(!p) return;
          if(/^\*\*[^*]+\*\*$/.test(p)) runs.push(T(p.slice(2,-2),{bold:true}));
          else if(/^`[^`]+`$/.test(p)) runs.push(T(p.slice(1,-1),{color:'7c3aed'}));
          else runs.push(T(p));
        });
        if(runs.length===0) runs.push(T(text));
        return runs;
      }

      function flushPara(){
        if(paraBuf.length>0){
          paras.push(P(inlineRuns(paraBuf.join(' '))));
          paraBuf = [];
        }
      }

      md.split('\n').forEach(function(line){
        var trimmed = line.trim();
        if(!trimmed){ flushPara(); return; }
        if(/^#/.test(trimmed)) return; // skip H tags (sections handled outside)
        var ulm = trimmed.match(/^[-*+]\s+(.+)$/);
        if(ulm){ flushPara(); paras.push(bullet(stripMd(ulm[1]))); return; }
        var olm = trimmed.match(/^(\d+)\.\s+(.+)$/);
        if(olm){
          flushPara();
          orderedCounter++;
          var content = stripMd(olm[2]);
          paras.push(new D.Paragraph({
            children:[T(orderedCounter+'.  ',{bold:true,color:'7c3aed',size:22}), T(content)],
            spacing:{after:100},
            indent:{left:200}
          }));
          return;
        }
        paraBuf.push(trimmed);
      });
      flushPara();
      if(paras.length===0) paras.push(P([T('— sección sin contenido —',{italics:true,color:'5f6368'})]));
      return paras;
    }

    // KPI table builder
    function kpiTable(rows){
      var trs = rows.map(function(r,i){
        var bg = i%2===0 ? 'F8F9FA' : 'FFFFFF';
        return new D.TableRow({children:[
          new D.TableCell({
            width:{size:65,type:D.WidthType.PERCENTAGE},
            shading:{fill:bg},
            children:[new D.Paragraph({children:[new D.TextRun({text:r[0],font:'Calibri',size:20})]})]
          }),
          new D.TableCell({
            width:{size:35,type:D.WidthType.PERCENTAGE},
            shading:{fill:bg},
            children:[new D.Paragraph({children:[new D.TextRun({text:String(r[1]),font:'Calibri',size:20,bold:true,color:'1a73e8'})]})]
          })
        ]});
      });
      return new D.Table({
        width:{size:100,type:D.WidthType.PERCENTAGE},
        rows:trs,
        borders:{
          top:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          bottom:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          left:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          right:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          insideHorizontal:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'},
          insideVertical:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'}
        }
      });
    }

    // Top vulns table
    function topVulnsTable(){
      var header = new D.TableRow({
        children:[
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'#',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'Vulnerabilidad',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'Hosts',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'KEV',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'VPR',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]})
        ]
      });
      var rows = ctx.topVulnerabilidades.map(function(v,i){
        var bg = i%2===0 ? 'F8F9FA' : 'FFFFFF';
        return new D.TableRow({children:[
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(i+1),font:'Calibri',size:18,bold:true})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:v.name,font:'Calibri',size:16})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(v.hosts),font:'Calibri',size:18,bold:true,color:'D93025'})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:v.kev?'SÍ':'—',font:'Calibri',size:16,bold:v.kev,color:v.kev?'7C3AED':'5F6368'})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(v.vpr||'—'),font:'Calibri',size:16})]})]})
        ]});
      });
      return new D.Table({
        width:{size:100,type:D.WidthType.PERCENTAGE},
        columnWidths:[600, 5800, 1100, 900, 1100],
        rows:[header].concat(rows),
        borders:{
          top:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          bottom:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          left:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          right:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          insideHorizontal:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'},
          insideVertical:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'}
        }
      });
    }

    // Tower table
    function towersTable(){
      var header = new D.TableRow({
        children:[
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'Torre',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'Hosts',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'Vulns',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'KEV',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'7C3AED'},children:[new D.Paragraph({children:[new D.TextRun({text:'SLA+15d',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]})
        ]
      });
      var rows = (ctx.porTorre||[]).map(function(t,i){
        var bg = i%2===0 ? 'F8F9FA' : 'FFFFFF';
        return new D.TableRow({children:[
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:t.name,font:'Calibri',size:18,bold:true})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(t.hosts),font:'Calibri',size:18})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(t.vulns),font:'Calibri',size:18})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(t.kev),font:'Calibri',size:18,color:t.kev>0?'7C3AED':'5F6368',bold:t.kev>0})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(t.crit),font:'Calibri',size:18,color:t.crit>0?'D93025':'5F6368',bold:t.crit>0})]})]})
        ]});
      });
      return new D.Table({
        width:{size:100,type:D.WidthType.PERCENTAGE},
        rows:[header].concat(rows),
        borders:{
          top:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          bottom:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          left:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          right:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          insideHorizontal:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'},
          insideVertical:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'}
        }
      });
    }

    // Environment table
    function envTable(){
      var header = new D.TableRow({
        children:[
          new D.TableCell({shading:{fill:'1A73E8'},children:[new D.Paragraph({children:[new D.TextRun({text:'Entorno',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'1A73E8'},children:[new D.Paragraph({children:[new D.TextRun({text:'Hosts',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'1A73E8'},children:[new D.Paragraph({children:[new D.TextRun({text:'Vulns',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'1A73E8'},children:[new D.Paragraph({children:[new D.TextRun({text:'KEV',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]}),
          new D.TableCell({shading:{fill:'1A73E8'},children:[new D.Paragraph({children:[new D.TextRun({text:'Críticos',font:'Calibri',size:18,bold:true,color:'FFFFFF'})]})]})
        ]
      });
      var rows = ctx.porEntorno.map(function(e,i){
        var bg = i%2===0 ? 'F8F9FA' : 'FFFFFF';
        return new D.TableRow({children:[
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:e.name,font:'Calibri',size:18,bold:true})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(e.hosts),font:'Calibri',size:18})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(e.vulns),font:'Calibri',size:18})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(e.kev),font:'Calibri',size:18,color:e.kev>0?'7C3AED':'5F6368',bold:e.kev>0})]})]}),
          new D.TableCell({shading:{fill:bg},children:[new D.Paragraph({children:[new D.TextRun({text:String(e.crit),font:'Calibri',size:18,color:e.crit>0?'D93025':'5F6368',bold:e.crit>0})]})]})
        ]});
      });
      return new D.Table({
        width:{size:100,type:D.WidthType.PERCENTAGE},
        rows:[header].concat(rows),
        borders:{
          top:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          bottom:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          left:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          right:{style:D.BorderStyle.SINGLE,size:4,color:'DADCE0'},
          insideHorizontal:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'},
          insideVertical:{style:D.BorderStyle.SINGLE,size:2,color:'E8EAED'}
        }
      });
    }

    var sec = [];

    // ── COVER ─────────────────────────────────────────────────────────────
    sec.push(P([T('Informe de Gestión',{bold:true,size:48,color:'1a73e8'})],{after:60,alignment:D.AlignmentType.CENTER}));
    sec.push(P([T('de Vulnerabilidades',{bold:true,size:48,color:'1a73e8'})],{after:200,alignment:D.AlignmentType.CENTER}));
    sec.push(P([T(ctx.meta.proveedor+' para '+ctx.meta.cliente,{size:28,color:'5f6368'})],{after:120,alignment:D.AlignmentType.CENTER}));
    sec.push(P([T('Snapshot: '+ctx.meta.snapshot,{size:20,color:'5f6368',italics:true})],{after:60,alignment:D.AlignmentType.CENTER}));
    sec.push(P([T('Fecha de emisión: '+ctx.meta.fecha,{size:20,color:'5f6368',italics:true})],{after:600,alignment:D.AlignmentType.CENTER}));

    // ── 1. RESUMEN EJECUTIVO ──────────────────────────────────────────────
    sec.push(H1('1. Resumen Ejecutivo'));
    sec = sec.concat(mdBlock(sections['Resumen Ejecutivo']));

    // ── 2. INDICADORES CLAVE ──────────────────────────────────────────────
    sec.push(H1('2. Indicadores Clave'));
    sec.push(P([T('Métricas deterministas extraídas directamente del último escaneo Qualys cargado.',{italics:true,color:'5f6368',size:20})],{after:140}));
    var k = ctx.kpis;
    sec.push(kpiTable([
      ['Parque total gestionado', k.parqueTotal],
      ['Equipos con vulnerabilidades', k.hostsConVulns + (k.coberturaPct!=null?' ('+k.coberturaPct+'% del parque)':'')],
      ['Vulnerabilidades activas (instancias)', k.totalVulns],
      ['Habilitados en Active Directory', k.habilitados],
      ['Deshabilitados con vulnerabilidades pendientes (fantasmas)', k.fantasmas],
      ['Hosts críticos (Q+AD >15 días)', k.criticos],
      ['Equipos abandonados (>90 días sin login)', k.abandonados],
      ['Antigüedad media del último escaneo', k.antiguedadMediaDias + ' días'],
      ['Vulnerabilidades CISA KEV activas', ctx.kev.vulnsActivas],
      ['Hosts afectados por CISA KEV', ctx.kev.hostsAfectados],
      ['Cumplimiento de SLA', ctx.sla?ctx.sla.cumplimientoPct+'%':'No configurado']
    ]));
    sec.push(P([],{after:200}));
    sec.push(img(charts.severidad, 540, 224));

    // ── 3. POSTURA DE RIESGO ──────────────────────────────────────────────
    sec.push(H1('3. Postura de Riesgo'));
    sec = sec.concat(mdBlock(sections['Postura de Riesgo']));
    if(charts.tendencia){
      sec.push(P([T('Evolución del número total de vulnerabilidades entre los snapshots cargados:',{italics:true,color:'5f6368',size:20})],{before:120,after:80}));
      sec.push(img(charts.tendencia, 540, 192));
    }

    // ── 4. EXPOSICIÓN CISA KEV ────────────────────────────────────────────
    sec.push(H1('4. Exposición CISA KEV'));
    sec = sec.concat(mdBlock(sections['Exposición CISA KEV']));
    if(ctx.kev.listado.length>0){
      sec.push(P([T('Listado de vulnerabilidades CISA KEV detectadas:',{bold:true})],{before:140,after:80}));
      ctx.kev.listado.forEach(function(v){ sec.push(bullet(v)); });
    }

    // ── 5. TOP VULNERABILIDADES ───────────────────────────────────────────
    sec.push(H1('5. Top Vulnerabilidades por Impacto'));
    sec.push(img(charts.topVulns, 580, 296));
    sec = sec.concat(mdBlock(sections['Top Vulnerabilidades por Impacto']));
    sec.push(P([T('Detalle tabular del Top 10:',{bold:true,size:20})],{before:160,after:80}));
    sec.push(topVulnsTable());

    // ── 6. ANÁLISIS POR ENTORNO ───────────────────────────────────────────
    sec.push(H1('6. Análisis por Entorno'));
    sec.push(img(charts.entornos, 580, Math.min(280, 80+ctx.porEntorno.length*32)));
    sec = sec.concat(mdBlock(sections['Análisis por Entorno']));
    sec.push(P([T('Detalle por entorno:',{bold:true,size:20})],{before:160,after:80}));
    sec.push(envTable());

    // ── 7. ANÁLISIS POR TORRE ────────────────────────────────────────────
    if(ctx.porTorre && ctx.porTorre.length){
      sec.push(H1('7. Análisis por Torre Responsable'));
      if(charts.torres) sec.push(img(charts.torres, 580, Math.min(280, 80+ctx.porTorre.length*32)));
      if(sections['Análisis por Torre']) sec = sec.concat(mdBlock(sections['Análisis por Torre']));
      sec.push(P([T('Detalle por torre:',{bold:true,size:20})],{before:160,after:80}));
      sec.push(towersTable());
    }

    // ── 8. HOSTS CRÍTICOS Y FANTASMAS ─────────────────────────────────────
    sec.push(H1('8. Hosts Críticos y Equipos Fantasma'));
    sec.push(img(charts.antiguedad, 540, 192));
    sec = sec.concat(mdBlock(sections['Hosts Críticos y Equipos Fantasma']));
    if(ctx.muestrasHosts.criticos.length>0){
      sec.push(P([T('Muestra de hosts críticos identificados:',{bold:true,size:20})],{before:140,after:60}));
      ctx.muestrasHosts.criticos.forEach(function(h){ sec.push(bullet(h)); });
    }
    if(ctx.muestrasHosts.fantasmas.length>0){
      sec.push(P([T('Muestra de equipos fantasma (DESHABILITADOS con vulnerabilidades):',{bold:true,size:20})],{before:140,after:60}));
      ctx.muestrasHosts.fantasmas.forEach(function(h){ sec.push(bullet(h)); });
    }

    // ── 9. RIESGOS EMERGENTES ─────────────────────────────────────────────
    sec.push(H1('9. Riesgos Emergentes'));
    sec = sec.concat(mdBlock(sections['Riesgos Emergentes']));

    // ── 10. RECOMENDACIONES OPERATIVAS ────────────────────────────────────
    sec.push(H1('10. Recomendaciones Operativas'));
    sec = sec.concat(mdBlock(sections['Recomendaciones Operativas']));

    // ── 11. CONCLUSIONES ──────────────────────────────────────────────────
    sec.push(H1('11. Conclusiones'));
    sec = sec.concat(mdBlock(sections['Conclusiones']));

    // ── FOOTER ────────────────────────────────────────────────────────────
    sec.push(P([],{after:300}));
    sec.push(P([T('Documento generado con asistencia de IA (Google Gemini). Revisión humana obligatoria antes de distribución.',{size:16,color:'5f6368',italics:true})],{alignment:D.AlignmentType.CENTER}));
    sec.push(P([T(ctx.meta.proveedor+' · Servicio para '+ctx.meta.cliente+' · '+ctx.meta.fecha,{size:14,color:'5f6368',italics:true})],{alignment:D.AlignmentType.CENTER}));

    var doc = new D.Document({
      styles:{default:{document:{run:{font:'Calibri',size:22}}}},
      sections:[{children:sec, properties:{page:{margin:{top:1200,right:1200,bottom:1000,left:1200}}}}]
    });
    var blob = await D.Packer.toBlob(doc);
    var a = window.document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'Informe_Vulnerabilidades_'+ctx.meta.fecha.replace(/\//g,'-')+'.docx';
    a.click();
  };

})();
