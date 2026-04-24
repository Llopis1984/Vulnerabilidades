// ══════════════════════════════════════════════════════════════════════════════
// WORKER — Inline Web Worker for CSV parsing (F1)
// ══════════════════════════════════════════════════════════════════════════════
var _csvWorker = null;
(function(){
  try {
    var wCode = [
      'function splitQ(line,sep){var r=[],c="",q=false;for(var i=0;i<line.length;i++){var ch=line[i];if(q){if(ch===\'"\')',
      '{if(i+1<line.length&&line[i+1]===\'"\'){c+=\'"\';i++;}else q=false;}else c+=ch;}else{if(ch===\'"\')q=true;else if(ch===sep){r.push(c);c="";}else c+=ch;}}r.push(c);return r;}',
      'function detectSep(h){var sc=0,cc=0,q=false;for(var i=0;i<h.length;i++){var c=h[i];if(c===\'"\'){q=!q;continue;}if(!q){if(c===";")sc++;else if(c===",")cc++;}}return sc>=cc?";":",";}',
      'function fi2(h,n){var nm=n.normalize("NFD").replace(/[\\u0300-\\u036f]/g,"").toLowerCase();return h.findIndex(function(x){return x.includes(nm);});}',
      'function g(c,i){return i>=0&&i<c.length?c[i].trim():"";}',
      'function normEnv(e){return(e||"Desconocido").replace(/^Endpoint-/i,"").trim().normalize("NFD").replace(/[\\u0300-\\u036f]/g,"");}',
      'function parseCVEs(str){return(str||"").split("|").map(function(s){return s.trim();}).filter(function(s){return /^CVE-/i.test(s);});}',
      'function pDate(s){if(!s)return null;var m=s.match(/(\\d{1,2})\\/(\\d{1,2})\\/(\\d{4})/);return m?new Date(+m[3],m[2]-1,+m[1]):null;}',
      'function dDiff(d){if(!d)return 999;var n=new Date();n.setHours(0,0,0,0);return Math.max(0,Math.floor((n-d)/864e5));}',
      'function parseCsv(text){',
      '  var lines=text.split(/\\r?\\n/).filter(function(l){return l.trim();});if(lines.length<2)return[];var sep=detectSep(lines[0]);',
      '  var hdr=splitQ(lines[0],sep).map(function(h){return h.trim().toLowerCase().normalize("NFD").replace(/[\\u0300-\\u036f]/g,"");});',
      '  var idx={vuln:fi2(hdr,"nombre vulnerabilidad"),host:fi2(hdr,"hostname"),ent:fi2(hdr,"entorno l2"),fesc:fi2(hdr,"fecha ultimo escaneo"),ead:fi2(hdr,"estado ad"),dlog:fi2(hdr,"dias logon"),res:fi2(hdr,"results"),sol:fi2(hdr,"solucion"),nvpr:fi2(hdr,"nivel vpr"),',
      '    cve:fi2(hdr,"cve"),fpub:fi2(hdr,"fecha publicacion"),fdet:fi2(hdr,"fecha deteccion"),fultdet:fi2(hdr,"fecha ultima deteccion"),fincump:fi2(hdr,"fecha incumplimiento"),estdet:fi2(hdr,"estado deteccion"),qid:fi2(hdr,"qid")};',
      '  if(idx.host<0){var i2={host:fi2(hdr,"hostname"),fesc:fi2(hdr,"fecha ultimo escaneo"),dq:fi2(hdr,"dias qualys"),ead:fi2(hdr,"estado ad"),dlog:fi2(hdr,"dias logon")};',
      '    if(i2.host>=0){return lines.slice(1).filter(function(l){return splitQ(l,sep).length>=5;}).map(function(l){var c=splitQ(l,sep);return{vulnName:"General",hostname:g(c,i2.host),entorno:"Desconocido",fechaEsc:g(c,i2.fesc),estadoAD:g(c,i2.ead)||"SIN ESTADO",diasLogon:parseInt(g(c,i2.dlog))||0,results:"",solucion:"",nivelVPR:"",diasQualys:parseInt(g(c,i2.dq))||0,cves:"",fechaPub:"",fechaDet:"",fechaUltDet:"",fechaIncump:"",estadoDet:"",qid:""};});}}',
      '  var rows=[];for(var i=1;i<lines.length;i++){var c=splitQ(lines[i],sep);if(c.length<5)continue;',
      '    rows.push({vulnName:g(c,idx.vuln),hostname:g(c,idx.host),entorno:g(c,idx.ent),fechaEsc:g(c,idx.fesc),estadoAD:g(c,idx.ead)||"SIN ESTADO",diasLogon:parseInt(g(c,idx.dlog))||0,results:g(c,idx.res),solucion:g(c,idx.sol),nivelVPR:g(c,idx.nvpr),',
      '      cves:g(c,idx.cve),fechaPub:g(c,idx.fpub),fechaDet:g(c,idx.fdet),fechaUltDet:g(c,idx.fultdet),fechaIncump:g(c,idx.fincump),estadoDet:g(c,idx.estdet),qid:g(c,idx.qid)});}return rows;',
      '}',
      'self.onmessage = function(e){',
      '  var d = e.data;',
      '  var firstLine = (d.text.split(/\\r?\\n/).find(function(l){return l.trim();}))||"";',
      '  var sep = detectSep(firstLine);',
      '  var rows = parseCsv(d.text);',
      '  rows.forEach(function(r){',
      '    r.entorno = normEnv(r.entorno);',
      '    if(r.diasQualys===undefined||r.diasQualys===0){var fd=pDate(r.fechaEsc);r.diasQualys=dDiff(fd);}',
      '    r._parsedCves = parseCVEs(r.cves);',
      '  });',
      '  self.postMessage({fileName:d.fileName, rows:rows, sep:sep});',
      '};'
    ].join('\n');
    var blob = new Blob([wCode], {type:'application/javascript'});
    _csvWorker = new Worker(URL.createObjectURL(blob));
    _csvWorker.onerror = function(err){ console.warn('[Worker] Error, fallback sync:', err.message); _csvWorker=null; };
    console.log('[F1] CSV Web Worker ready');
  } catch(ex){ console.warn('[F1] Web Worker not available:', ex.message); }
})();

function _sendToWorkerOrSync(fileName, txt, pf, pfOrder){
  if(_csvWorker){
    // Worker will postMessage back — handled in core.js via onmessage
    _csvWorker.postMessage({fileName:fileName, text:txt});
  } else {
    // Fallback síncrono
    var firstLine = (txt.split(/\r?\n/).find(function(l){return l.trim();}))||'';
    var sep = detectSep(firstLine);
    var rows = parseCsv(txt);
    if(rows.length<2){
      var er=document.getElementById('uplE');er.textContent=fileName+': sin datos ('+rows.length+')';er.style.display='block';return;
    }
    pf.set(fileName,{name:fileName, rows:rows, sep:sep});
    if(!pfOrder.includes(fileName)) pfOrder.push(fileName);
    rfList();
  }
}
