// GEMINI 3 PRO — Cliente para análisis IA
// Documentación: https://ai.google.dev/gemini-api/docs/gemini-3
(function(){
  var GEMINI_KEY_STORAGE = 'gemini_api_key_v1';
  var GEMINI_MODEL = 'gemini-3-flash-preview';
  var GEMINI_FALLBACK = 'gemini-2.5-flash';
  var GEMINI_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models/';

  // ── API Key management ──
  window._geminiGetKey = function(){
    try { return localStorage.getItem(GEMINI_KEY_STORAGE) || ''; } catch(e){ return ''; }
  };
  window._geminiSetKey = function(key){
    try { localStorage.setItem(GEMINI_KEY_STORAGE, key); } catch(e){}
  };
  window._geminiClearKey = function(){
    try { localStorage.removeItem(GEMINI_KEY_STORAGE); } catch(e){}
  };
  window._geminiHasKey = function(){
    return !!window._geminiGetKey();
  };

  // ── API Key Modal ──
  window._geminiOpenKeyModal = function(onSaved){
    // Remove existing
    var existing = document.getElementById('geminiKeyModal'); if(existing) existing.remove();

    var currentKey = window._geminiGetKey();
    var maskedKey = currentKey ? currentKey.substring(0,8)+'•••••••••'+currentKey.substring(currentKey.length-4) : '';

    var modal = document.createElement('div');
    modal.id = 'geminiKeyModal';
    modal.style.cssText = 'position:fixed;inset:0;background:var(--modal-bg);z-index:2000;display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeScale .2s ease';
    modal.innerHTML =
      '<div style="background:var(--s1);border-radius:18px;box-shadow:0 12px 40px rgba(0,0,0,.25);max-width:520px;width:100%;overflow:hidden">'
      +'<div style="padding:22px 26px 16px;border-bottom:1px solid var(--olv);display:flex;align-items:center;gap:12px">'
      +'<div style="width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,#7c3aed,#a855f7);display:grid;place-items:center;flex-shrink:0"><span class="material-icons-round" style="color:#fff;font-size:22px">key</span></div>'
      +'<div style="flex:1"><div style="font-family:var(--fd);font-size:1.05rem;font-weight:700">Conectar con Google Gemini</div><div style="font-size:.72rem;color:var(--t2);margin-top:2px">Necesario para análisis IA en tiempo real</div></div>'
      +'<button onclick="document.getElementById(\'geminiKeyModal\').remove()" style="background:none;border:none;cursor:pointer;color:var(--t2);width:32px;height:32px;border-radius:50%;display:grid;place-items:center;transition:background .15s" onmouseover="this.style.background=\'var(--s2)\'" onmouseout="this.style.background=\'transparent\'"><span class="material-icons-round" style="font-size:20px">close</span></button>'
      +'</div>'
      +'<div style="padding:22px 26px">'
      +(currentKey ? '<div style="background:var(--okc);border:1px solid rgba(26,122,50,.2);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:.78rem;color:var(--ok);display:flex;align-items:center;gap:8px"><span class="material-icons-round" style="font-size:16px">check_circle</span>API Key configurada: <code style="font-family:var(--fd);font-size:.72rem">'+maskedKey+'</code></div>' : '')
      +'<label style="display:block;font-family:var(--fd);font-size:.78rem;font-weight:600;margin-bottom:6px">Google AI Studio API Key</label>'
      +'<div style="position:relative">'
      +'<input type="password" id="geminiKeyInput" placeholder="AIzaSy..." value="'+currentKey+'" style="width:100%;padding:11px 40px 11px 14px;border:2px solid var(--ol);border-radius:11px;font-family:Monaco,monospace;font-size:.85rem;background:var(--s1);color:var(--t);outline:none;transition:border-color .2s" onfocus="this.style.borderColor=\'#7c3aed\'" onblur="this.style.borderColor=\'var(--ol)\'">'
      +'<button onclick="var i=document.getElementById(\'geminiKeyInput\');i.type=i.type===\'password\'?\'text\':\'password\'" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--t2);width:28px;height:28px;border-radius:50%;display:grid;place-items:center" title="Mostrar/ocultar"><span class="material-icons-round" style="font-size:16px">visibility</span></button>'
      +'</div>'
      +'<div style="font-size:.68rem;color:var(--t2);margin-top:8px;line-height:1.5">'
      +'• La clave se guarda únicamente en tu navegador (localStorage)<br>'
      +'• No se envía a ningún servidor externo excepto a Google Gemini<br>'
      +'• Obtén una clave gratuita en <a href="https://aistudio.google.com/app/apikey" target="_blank" style="color:#7c3aed;text-decoration:none;font-weight:500">aistudio.google.com/app/apikey</a>'
      +'</div>'
      +'<div style="margin-top:14px;padding:10px 14px;background:var(--s2);border-radius:10px;font-size:.68rem;color:var(--t2);display:flex;gap:8px;align-items:flex-start">'
      +'<span class="material-icons-round" style="font-size:14px;color:var(--p);flex-shrink:0;margin-top:1px">info</span>'
      +'<span>Modelo en uso: <strong style="color:var(--t)">'+GEMINI_MODEL+'</strong> · Optimizado para razonamiento y análisis de texto largo</span>'
      +'</div>'
      +'<div id="geminiKeyError" style="display:none;margin-top:12px;padding:10px 14px;background:var(--errc);border-radius:8px;color:var(--err);font-size:.72rem"></div>'
      +'</div>'
      +'<div style="padding:14px 26px 22px;display:flex;gap:8px;justify-content:flex-end">'
      +(currentKey ? '<button onclick="window._geminiClearKey();document.getElementById(\'geminiKeyModal\').remove();window.dispatchEvent(new CustomEvent(\'gemini-key-cleared\'))" style="padding:10px 18px;border-radius:22px;border:1.5px solid var(--err);background:transparent;color:var(--err);font-family:var(--fd);font-size:.78rem;font-weight:500;cursor:pointer">Eliminar clave</button>' : '')
      +'<button onclick="window._geminiTestAndSave()" id="geminiSaveBtn" style="padding:10px 22px;border-radius:22px;border:none;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-family:var(--fd);font-size:.82rem;font-weight:600;cursor:pointer;box-shadow:0 2px 8px rgba(124,58,237,.3)">Guardar y validar</button>'
      +'</div>'
      +'</div>';

    document.body.appendChild(modal);
    modal.addEventListener('click', function(e){ if(e.target === modal) modal.remove(); });

    if(onSaved) window._geminiOnSaved = onSaved;
    setTimeout(function(){ document.getElementById('geminiKeyInput').focus(); }, 100);
  };

  // Test API key with a tiny request, then save
  window._geminiTestAndSave = async function(){
    var input = document.getElementById('geminiKeyInput');
    var errEl = document.getElementById('geminiKeyError');
    var btn = document.getElementById('geminiSaveBtn');
    var key = input.value.trim();
    if(!key){
      errEl.textContent = 'Introduce una API key válida';
      errEl.style.display = 'block';
      return;
    }
    errEl.style.display = 'none';
    btn.disabled = true;
    btn.innerHTML = '<span class="material-icons-round" style="font-size:16px;animation:spin 1s linear infinite;vertical-align:-3px">autorenew</span> Validando...';

    try {
      var resp = await fetch(GEMINI_ENDPOINT + GEMINI_MODEL + ':generateContent', {
        method: 'POST',
        headers: { 'x-goog-api-key': key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: 'Responde solo con: OK' }] }] })
      });
      if(!resp.ok){
        var errData = await resp.json().catch(function(){ return {}; });
        var msg = errData.error && errData.error.message ? errData.error.message : 'HTTP '+resp.status;
        // Try fallback model if flash preview not available
        if(resp.status === 404){
          var fallback = await fetch(GEMINI_ENDPOINT + GEMINI_FALLBACK + ':generateContent', {
            method: 'POST',
            headers: { 'x-goog-api-key': key, 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: [{ text: 'OK' }] }] })
          });
          if(fallback.ok){
            window._geminiSetKey(key);
            window._geminiActiveModel = GEMINI_FALLBACK;
            try { localStorage.setItem('gemini_active_model', GEMINI_FALLBACK); } catch(e){}
            document.getElementById('geminiKeyModal').remove();
            if(window._geminiOnSaved) window._geminiOnSaved();
            return;
          }
        }
        throw new Error(msg);
      }
      // Success
      window._geminiSetKey(key);
      window._geminiActiveModel = GEMINI_MODEL;
      try { localStorage.setItem('gemini_active_model', GEMINI_MODEL); } catch(e){}
      document.getElementById('geminiKeyModal').remove();
      if(window._geminiOnSaved) window._geminiOnSaved();
    } catch(e){
      errEl.textContent = 'Error: ' + (e.message || 'No se pudo validar la clave');
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.innerHTML = 'Guardar y validar';
    }
  };

  // ── Gemini call ──
  // promptText: el texto del prompt
  // systemInstruction: instrucción de sistema (opcional)
  // options: { responseSchema, temperature, maxOutputTokens, json: true }
  window._geminiAsk = async function(promptText, systemInstruction, options){
    options = options || {};
    var key = window._geminiGetKey();
    if(!key) throw new Error('NO_KEY');

    var model = window._geminiActiveModel || (function(){
      try {
        var saved = localStorage.getItem('gemini_active_model');
        // Force migration off the old expensive Pro model
        if(saved === 'gemini-3-pro-preview' || saved === 'gemini-2.5-pro') return GEMINI_MODEL;
        return saved || GEMINI_MODEL;
      } catch(e){ return GEMINI_MODEL; }
    })();

    var body = {
      contents: [{ parts: [{ text: promptText }] }]
    };
    if(systemInstruction){
      body.systemInstruction = { parts: [{ text: systemInstruction }] };
    }
    body.generationConfig = {
      temperature: options.temperature != null ? options.temperature : 0.4,
      maxOutputTokens: options.maxOutputTokens || 8192
    };
    if(options.json || options.responseSchema){
      body.generationConfig.responseMimeType = 'application/json';
    }
    if(options.responseSchema){
      body.generationConfig.responseSchema = options.responseSchema;
    }

    var resp = await fetch(GEMINI_ENDPOINT + model + ':generateContent', {
      method: 'POST',
      headers: { 'x-goog-api-key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if(!resp.ok){
      var errData = await resp.json().catch(function(){ return {}; });
      var msg = errData.error && errData.error.message ? errData.error.message : 'HTTP '+resp.status;
      throw new Error(msg);
    }

    var data = await resp.json();
    var text = '';
    if(data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts){
      text = data.candidates[0].content.parts.map(function(p){ return p.text || ''; }).join('');
    }
    return text;
  };

  // ── Gemini streaming call ──
  // Lee la respuesta chunk a chunk usando response.body.getReader() y SSE
  // callbacks: { onChunk(chunkText, fullText), onDone(fullText), onError(err) }
  window._geminiAskStream = async function(promptText, systemInstruction, options, callbacks){
    options = options || {}; callbacks = callbacks || {};
    var key = window._geminiGetKey();
    if(!key){ if(callbacks.onError) callbacks.onError(new Error('NO_KEY')); return; }

    var model = window._geminiActiveModel || (function(){
      try {
        var saved = localStorage.getItem('gemini_active_model');
        if(saved === 'gemini-3-pro-preview' || saved === 'gemini-2.5-pro') return GEMINI_MODEL;
        return saved || GEMINI_MODEL;
      } catch(e){ return GEMINI_MODEL; }
    })();

    var body = { contents: [{ parts: [{ text: promptText }] }] };
    if(systemInstruction){ body.systemInstruction = { parts: [{ text: systemInstruction }] }; }
    body.generationConfig = {
      temperature: options.temperature != null ? options.temperature : 0.4,
      maxOutputTokens: options.maxOutputTokens || 8192
    };
    if(options.json || options.responseSchema){
      body.generationConfig.responseMimeType = 'application/json';
    }
    if(options.responseSchema){
      body.generationConfig.responseSchema = options.responseSchema;
    }

    try {
      // Streaming endpoint with SSE format
      var resp = await fetch(GEMINI_ENDPOINT + model + ':streamGenerateContent?alt=sse', {
        method: 'POST',
        headers: { 'x-goog-api-key': key, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      if(!resp.ok){
        var errData = await resp.json().catch(function(){ return {}; });
        var msg = errData.error && errData.error.message ? errData.error.message : 'HTTP '+resp.status;
        throw new Error(msg);
      }

      var reader = resp.body.getReader();
      var decoder = new TextDecoder('utf-8');
      var buffer = '';
      var fullText = '';

      while(true){
        var result = await reader.read();
        if(result.done) break;

        buffer += decoder.decode(result.value, { stream: true });

        // SSE format: each event separated by double newline, lines start with "data: "
        var lines = buffer.split('\n');
        // Keep last (possibly incomplete) line in buffer
        buffer = lines.pop();

        for(var i=0; i<lines.length; i++){
          var line = lines[i].trim();
          if(!line) continue;
          if(line.indexOf('data:') !== 0) continue;
          var payload = line.slice(5).trim();
          if(!payload || payload === '[DONE]') continue;
          try {
            var json = JSON.parse(payload);
            if(json.candidates && json.candidates[0] && json.candidates[0].content && json.candidates[0].content.parts){
              var chunkText = json.candidates[0].content.parts.map(function(p){ return p.text || ''; }).join('');
              if(chunkText){
                fullText += chunkText;
                if(callbacks.onChunk) callbacks.onChunk(chunkText, fullText);
              }
            }
          } catch(e){
            // Ignore malformed chunks (partial JSON in buffer)
          }
        }
      }

      // Flush any remaining buffer
      if(buffer && buffer.indexOf('data:') === 0){
        try {
          var lastJson = JSON.parse(buffer.slice(5).trim());
          if(lastJson.candidates && lastJson.candidates[0] && lastJson.candidates[0].content && lastJson.candidates[0].content.parts){
            var lastChunk = lastJson.candidates[0].content.parts.map(function(p){ return p.text || ''; }).join('');
            if(lastChunk){
              fullText += lastChunk;
              if(callbacks.onChunk) callbacks.onChunk(lastChunk, fullText);
            }
          }
        } catch(e){}
      }

      if(callbacks.onDone) callbacks.onDone(fullText);
    } catch(e){
      if(callbacks.onError) callbacks.onError(e);
    }
  };
})();
