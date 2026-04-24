// ══════════════════════════════════════════════════════════════════════════════
// STORAGE — IndexedDB para persistir snapshots entre sesiones
// ══════════════════════════════════════════════════════════════════════════════
var VDB = (function(){
  var DB_NAME = 'vuln_dashboard_v1';
  var DB_VERSION = 2;
  var SNAP_STORE = 'snapshots';
  var NOTES_STORE = 'notes';
  var CHECKLIST_STORE = 'checklist';
  var TOWER_CACHE_STORE = 'tower_cache_v1';
  var db = null;

  function open(){
    return new Promise(function(resolve, reject){
      if(db){ resolve(db); return; }
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function(e){
        var d = e.target.result;
        if(!d.objectStoreNames.contains(SNAP_STORE)){
          d.createObjectStore(SNAP_STORE, {keyPath:'id', autoIncrement:true});
        }
        if(!d.objectStoreNames.contains(NOTES_STORE)){
          d.createObjectStore(NOTES_STORE, {keyPath:'vulnName'});
        }
        if(!d.objectStoreNames.contains(CHECKLIST_STORE)){
          d.createObjectStore(CHECKLIST_STORE, {keyPath:'hostname'});
        }
        if(!d.objectStoreNames.contains(TOWER_CACHE_STORE)){
          d.createObjectStore(TOWER_CACHE_STORE, {keyPath:'vulnKey'});
        }
      };
      req.onsuccess = function(e){ db = e.target.result; resolve(db); };
      req.onerror = function(e){ console.warn('[IDB] Error:', e); reject(e); };
    });
  }

  // ── Tower classification cache ──
  function getTowerCache(vulnKey){
    return open().then(function(d){
      return new Promise(function(resolve){
        if(!d.objectStoreNames.contains(TOWER_CACHE_STORE)){ resolve(null); return; }
        var tx = d.transaction(TOWER_CACHE_STORE, 'readonly');
        var req = tx.objectStore(TOWER_CACHE_STORE).get(vulnKey);
        req.onsuccess = function(){
          var r = req.result;
          resolve(r ? { torre: r.torre, conf: r.conf, fuente: r.fuente, ts: r.ts } : null);
        };
        req.onerror = function(){ resolve(null); };
      });
    });
  }

  function setTowerCache(vulnKey, entry){
    return open().then(function(d){
      return new Promise(function(resolve){
        if(!d.objectStoreNames.contains(TOWER_CACHE_STORE)){ resolve(); return; }
        var tx = d.transaction(TOWER_CACHE_STORE, 'readwrite');
        tx.objectStore(TOWER_CACHE_STORE).put({ vulnKey: vulnKey, torre: entry.torre, conf: entry.conf, fuente: entry.fuente, ts: entry.ts || Date.now() });
        tx.oncomplete = function(){ resolve(); };
        tx.onerror = function(){ resolve(); };
      });
    });
  }

  function clearTowerCache(){
    return open().then(function(d){
      return new Promise(function(resolve){
        if(!d.objectStoreNames.contains(TOWER_CACHE_STORE)){ resolve(); return; }
        var tx = d.transaction(TOWER_CACHE_STORE, 'readwrite');
        tx.objectStore(TOWER_CACHE_STORE).clear();
        tx.oncomplete = function(){ resolve(); };
      });
    });
  }

  // ── Snapshots ──
  function saveSnapshot(name, rows, meta){
    return open().then(function(d){
      return new Promise(function(resolve, reject){
        var tx = d.transaction(SNAP_STORE, 'readwrite');
        var st = tx.objectStore(SNAP_STORE);
        var entry = {
          name: name,
          date: new Date().toISOString(),
          rowCount: rows.length,
          rows: rows,
          meta: meta || {}
        };
        var req = st.add(entry);
        req.onsuccess = function(){ resolve(req.result); };
        req.onerror = function(e){ reject(e); };
      });
    });
  }

  function listSnapshots(){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(SNAP_STORE, 'readonly');
        var st = tx.objectStore(SNAP_STORE);
        var req = st.getAll();
        req.onsuccess = function(){
          // Return metadata only (not rows) for listing
          var list = (req.result||[]).map(function(s){
            return {id:s.id, name:s.name, date:s.date, rowCount:s.rowCount, meta:s.meta};
          });
          resolve(list);
        };
        req.onerror = function(){ resolve([]); };
      });
    });
  }

  function loadSnapshot(id){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(SNAP_STORE, 'readonly');
        var req = tx.objectStore(SNAP_STORE).get(id);
        req.onsuccess = function(){ resolve(req.result||null); };
        req.onerror = function(){ resolve(null); };
      });
    });
  }

  function deleteSnapshot(id){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(SNAP_STORE, 'readwrite');
        tx.objectStore(SNAP_STORE).delete(id);
        tx.oncomplete = function(){ resolve(); };
      });
    });
  }

  // ── Notas por vulnerabilidad ──
  function saveNote(vulnName, text, meta){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(NOTES_STORE, 'readwrite');
        tx.objectStore(NOTES_STORE).put({vulnName:vulnName, text:text, date:new Date().toISOString(), meta:meta||{}});
        tx.oncomplete = function(){ resolve(); };
      });
    });
  }

  function getNote(vulnName){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(NOTES_STORE, 'readonly');
        var req = tx.objectStore(NOTES_STORE).get(vulnName);
        req.onsuccess = function(){ resolve(req.result||null); };
        req.onerror = function(){ resolve(null); };
      });
    });
  }

  function getAllNotes(){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(NOTES_STORE, 'readonly');
        var req = tx.objectStore(NOTES_STORE).getAll();
        req.onsuccess = function(){ resolve(req.result||[]); };
        req.onerror = function(){ resolve([]); };
      });
    });
  }

  function deleteNote(vulnName){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(NOTES_STORE, 'readwrite');
        tx.objectStore(NOTES_STORE).delete(vulnName);
        tx.oncomplete = function(){ resolve(); };
      });
    });
  }

  // ── Checklist post-parche ──
  function saveCheck(hostname, data){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(CHECKLIST_STORE, 'readwrite');
        tx.objectStore(CHECKLIST_STORE).put(Object.assign({hostname:hostname, date:new Date().toISOString()}, data));
        tx.oncomplete = function(){ resolve(); };
      });
    });
  }

  function getAllChecks(){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(CHECKLIST_STORE, 'readonly');
        var req = tx.objectStore(CHECKLIST_STORE).getAll();
        req.onsuccess = function(){ resolve(req.result||[]); };
        req.onerror = function(){ resolve([]); };
      });
    });
  }

  function clearChecks(){
    return open().then(function(d){
      return new Promise(function(resolve){
        var tx = d.transaction(CHECKLIST_STORE, 'readwrite');
        tx.objectStore(CHECKLIST_STORE).clear();
        tx.oncomplete = function(){ resolve(); };
      });
    });
  }

  return {
    saveSnapshot:saveSnapshot, listSnapshots:listSnapshots,
    loadSnapshot:loadSnapshot, deleteSnapshot:deleteSnapshot,
    saveNote:saveNote, getNote:getNote, getAllNotes:getAllNotes, deleteNote:deleteNote,
    saveCheck:saveCheck, getAllChecks:getAllChecks, clearChecks:clearChecks,
    getTowerCache:getTowerCache, setTowerCache:setTowerCache, clearTowerCache:clearTowerCache
  };
})();

// ── Auto-guardar snapshot tras cargar CSV ──
window._autoSaveSnapshot = function(name, rows){
  VDB.saveSnapshot(name, rows, {totalDevices:totalDevices||0}).then(function(id){
    console.log('[IDB] Snapshot guardado: '+name+' (id='+id+', '+rows.length+' filas)');
  }).catch(function(e){ console.warn('[IDB] Error guardando snapshot:', e); });
};

// ── Cargar snapshots guardados en la pantalla de inicio ──
window._loadSavedSnapshots = function(){
  var container = document.getElementById('savedSnapshotsArea');
  if(!container) return;
  VDB.listSnapshots().then(function(list){
    if(!list.length){ container.innerHTML=''; container.style.display='none'; return; }
    container.style.display='block';
    var h='<div style="font-family:var(--fd);font-size:.80rem;font-weight:500;margin-bottom:8px;display:flex;align-items:center;gap:6px"><span class="material-icons-round" style="font-size:16px;color:var(--p)">history</span> Snapshots guardados ('+list.length+')</div>';
    h+='<div style="display:flex;flex-direction:column;gap:4px">';
    list.forEach(function(s){
      var d=new Date(s.date).toLocaleString('es-ES');
      h+='<div style="display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--s2);border-radius:8px;font-size:.73rem">'
        +'<span class="material-icons-round" style="font-size:14px;color:var(--ok)">inventory_2</span>'
        +'<span style="flex:1;font-weight:500">'+s.name+'</span>'
        +'<span style="color:var(--t2)">'+s.rowCount+' filas · '+d+'</span>'
        +'<button onclick="window._restoreSnapshot('+s.id+')" style="background:var(--p);color:#fff;border:none;padding:3px 10px;border-radius:10px;font-size:.68rem;font-family:var(--fd);cursor:pointer">Cargar</button>'
        +'<button onclick="window._deleteSnapshot('+s.id+')" style="background:none;border:none;color:var(--t2);cursor:pointer;padding:2px" title="Eliminar"><span class="material-icons-round" style="font-size:14px">delete</span></button>'
        +'</div>';
    });
    h+='</div>';
    container.innerHTML=h;
  });
};

window._restoreSnapshot = function(id){
  VDB.loadSnapshot(id).then(function(snap){
    if(!snap||!snap.rows){ alert('Snapshot no encontrado'); return; }
    pf.set(snap.name, {name:snap.name, rows:snap.rows, sep:';', _processed:true});
    if(!pfOrder.includes(snap.name)) pfOrder.push(snap.name);
    rfList();
  });
};

window._deleteSnapshot = function(id){
  if(!confirm('¿Eliminar este snapshot?')) return;
  VDB.deleteSnapshot(id).then(function(){ window._loadSavedSnapshots(); });
};
