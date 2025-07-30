document.addEventListener('DOMContentLoaded', () => {
  const filepathInput = document.getElementById('filepath');
  const loadBtn = document.getElementById('load-btn');
  const symbolTreeDiv = document.getElementById('symbol-tree');
  const listingDiv = document.getElementById('listing');
  // Search controls
  const searchInput = document.getElementById('search-term');
  const searchBtn = document.getElementById('search-btn');
  const filterToggle = document.getElementById('filter-toggle');
  
  // Loading indicator elements
  const loadingOverlay = document.getElementById('loading-overlay');
  const loadingText = document.getElementById('loading-text');
  
  // Loading indicator functions
  function showLoading(message = 'Loading...') {
    loadingText.textContent = message;
    loadingOverlay.classList.add('show');
  }
  
  function hideLoading() {
    loadingOverlay.classList.remove('show');
  }

  function clearFilter() {
    const lines = listingDiv.querySelectorAll('.asm-line');
    lines.forEach(line => {
      line.style.display = '';
    });
  }

  // Helper to clear existing highlights
  function clearHighlights() {
    const highlights = listingDiv.querySelectorAll('.search-highlight');
    highlights.forEach(span => {
      const parent = span.parentNode;
      parent.replaceChild(document.createTextNode(span.textContent), span);
      parent.normalize();
    });
  }

  // Highlight all occurrences of the term within the listing
  function highlightTerm(term) {
    if (!term) return;
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escaped, 'gi');

    // Walk through text nodes under listingDiv
    const walker = document.createTreeWalker(listingDiv, NodeFilter.SHOW_TEXT, null, false);
    const textNodes = [];
    while (walker.nextNode()) {
      textNodes.push(walker.currentNode);
    }

    textNodes.forEach(node => {
      const text = node.data;
      regex.lastIndex = 0; // reset for each node
      if (!regex.test(text)) return;

      const frag = document.createDocumentFragment();
      let lastIndex = 0;
      text.replace(regex, (match, offset) => {
        // Text before match
        if (offset > lastIndex) {
          frag.appendChild(document.createTextNode(text.slice(lastIndex, offset)));
        }
        // Matched term wrapped in span
        const span = document.createElement('span');
        span.className = 'search-highlight';
        span.textContent = match;
        frag.appendChild(span);
        lastIndex = offset + match.length;
      });
      // Remaining text after last match
      if (lastIndex < text.length) {
        frag.appendChild(document.createTextNode(text.slice(lastIndex)));
      }
      node.parentNode.replaceChild(frag, node);
    });
  }

  function performSearch() {
    clearHighlights();
    clearFilter();
    const term = searchInput.value.trim();
    if (!term) return;
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escaped, 'i');
    if (filterToggle && filterToggle.checked) {
      // Hide lines not matching term
      const lines = listingDiv.querySelectorAll('.asm-line');
      lines.forEach(line => {
        if (!regex.test(line.textContent)) {
          line.style.display = 'none';
        }
      });
    }
    highlightTerm(term);
    // Scroll to first match for convenience
    const first = listingDiv.querySelector('.search-highlight');
    if (first) {
      first.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  // Bind search events
  if (searchBtn && searchInput) {
    searchBtn.addEventListener('click', performSearch);
    searchInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        performSearch();
      }
    });
  }

  if (filterToggle) {
    filterToggle.addEventListener('change', () => {
      // Re-run search when filter option toggled
      performSearch();
    });
  }

  let currentFile = '';
  let functions = [];
  let fullDisasmHTML = '';

  loadBtn.addEventListener('click', async () => {
    currentFile = filepathInput.value.trim();
    if (!currentFile) {
      listingDiv.textContent = 'Please provide a file path.';
      return;
    }
    symbolTreeDiv.innerHTML = 'Loading...';
    listingDiv.textContent = 'Output will appear here.';
    try {
      showLoading('Loading and analyzing binary...');
      await loadSymbols();
    } catch (error) {
      symbolTreeDiv.innerHTML = `Error loading symbols: ${error.message}`;
      console.error('Error:', error);
    } finally {
      hideLoading();
    }
  });

  async function radare2Request(params) {
    try {
      console.log('Sending radare2 request with params:', params);
      const res = await fetch('http://localhost:8080/radare2', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filepath: currentFile, params })
      });
      const data = await res.json();
      console.log('Raw radare2 response:', data);
      if (data.error) {
        throw new Error(data.error);
      }
      return data;
    } catch (error) {
      console.error('Radare2 request failed:', error);
      throw error;
    }
  }

  function formatDisassembly(disasm) {
    // Remove ANSI color codes
    disasm = disasm.replace(/\x1b\[[0-9;]*m/g, '');
    
    const lines = disasm.split('\n');
    let html = '<div class="asm-container">';
    let inFunction = false;
    let lineCounter = 0;   // For sequential numbering
    let pendingOffset = null; // To store offset coming in separate line (e.g., x000010a0)

    for (const line of lines) {
      let trimmedLine = line.trim();
      if (!trimmedLine) continue;

      // Strip leading numeric index with optional colon, e.g., "37:" or "0:"
      trimmedLine = trimmedLine.replace(/^\d+:?\s*/, '');
      if (!trimmedLine) continue; // If nothing left, skip line

      // Filter out radare warnings / extraneous lines
      if (trimmedLine.startsWith('WARN') || trimmedLine.startsWith('INFO') || trimmedLine.toLowerCase().includes('operable')) {
        continue;
      }

      // Skip lines that are just zeros produced by r2 when asm.lines=false
      if (/^0+$/.test(trimmedLine)) continue;

      // Handle lines that are only an address like "x000010a0" (without leading 0)
      if (/^x[0-9a-fA-F]+$/.test(trimmedLine)) {
        pendingOffset = '0' + trimmedLine; // Prepend missing 0
        continue; // Next line will contain bytes/mnemonic
      }

      // Skip invalid instructions
      if (trimmedLine.includes('invalid')) continue;

      // Handle function headers (e.g. "/ (fcn) sym.main ()")
      if (trimmedLine.startsWith('/') && trimmedLine.includes('(fcn)')) {
        if (inFunction) {
          html += '</div>'; // Close previous function
        }
        inFunction = true;
        const funcName = trimmedLine.split('(fcn)')[1].trim().split(' ')[0];
        html += `<div class="asm-function">`;
        html += `<div class="asm-function-header"><span class="asm-section">Function: ${funcName}</span></div>`;
        continue;
      }

      // Handle section headers
      if (trimmedLine.startsWith('section.')) {
        const sectionName = trimmedLine.split(':')[0] || '';
        html += `<div class="asm-line"><span class="asm-section">${sectionName}:</span></div>`;
        continue;
      }

      // Try to parse the disassembly line
      // More flexible regex to catch various assembly line formats
      const match = trimmedLine.match(/^([0-9a-fA-F]+)?\s*([0-9a-fA-F ]+)?\s*([a-z]+[.]*[a-z0-9]*)?\s*([^;]+)?(?:;\s*(.+))?$/i);
      
      if (!match) {
        // If line doesn't match expected format, output as plain text
        html += `<div class="asm-line"><span class="asm-text">${trimmedLine}</span></div>`;
        continue;
      }

      let [_, offset, bytes, mnemonic, operands, comment] = match;
      
      // Use pending offset if present
      if (!offset && pendingOffset) {
        offset = pendingOffset;
        pendingOffset = null;
      }

      // Skip empty instructions
      if (!mnemonic && !bytes && !offset) continue;

      // Increment and display line number
      const lineNoSpan = `<span class="asm-lineno">${lineCounter}</span>`;
      lineCounter += 1;

      offset = (offset || '').trim();
      bytes = (bytes || '').trim();
      mnemonic = (mnemonic || '').trim();
      operands = (operands || '').trim();
      
      // Format the operands - highlight registers and addresses
      const formattedOperands = operands
        .replace(/\b(e?[abcd]x|[abcd]l|[abcd]h|e?[sd]i|e?[sb]p|e?ip|r[0-9]+[dwb]?)\b/g, '<span class="r2-register">$1</span>')
        .replace(/\b(section\.[^\s,]+)\b/g, '<span class="asm-section">$1</span>')
        .replace(/\b(0x[0-9a-fA-F]+)\b/g, '<span class="asm-address">$1</span>');

      html += `<div class="asm-line">${lineNoSpan}`;
      if (offset) html += `<span class="asm-address">${offset}</span>`;
      if (bytes) html += `<span class="asm-bytes">${bytes}</span>`;
      if (mnemonic) html += `<span class="asm-instruction">${mnemonic}</span>`;
      if (operands) html += `<span class="asm-operands">${formattedOperands}</span>`;
      if (comment) html += `<span class="asm-comment">;${comment}</span>`;
      html += '</div>';
    }

    if (inFunction) {
      html += '</div>'; // Close last function
    }

    html += '</div>';
    return html;
  }

  // Remove ANSI codes and generic WARN/INFO or shell noise lines from radare2 text output
  function cleanRadareOutput(text) {
    if (!text) return '';
    // Strip ANSI color codes
    text = text.replace(/\x1b\[[0-9;]*m/g, '');
    return text
      .split('\n')
      .filter(line => {
        const lower = line.trim().toLowerCase();
        if (!lower) return false; // drop empty
        if (lower.includes('warn') || lower.includes('info')) return false;
        if (lower.includes('operable') || lower.includes('chcp')) return false;
        return true;
      })
      .join('\n');
  }

  // Helper: remove ANSI, warnings, and extract JSON array
  function parseJsonArray(output) {
    if (!output) return null;
    // Strip ANSI color codes
    let cleaned = output.replace(/\x1b\[[0-9;]*m/g, '');
    // Drop warn/info/shell noise lines
    cleaned = cleaned.split('\n').filter(l => {
      const t = l.trim();
      if (!t) return false;
      if (t.toLowerCase().startsWith('warn')) return false;
      if (t.toLowerCase().startsWith('info')) return false;
      if (t.includes('operable') || t.includes('chcp')) return false;
      return true;
    }).join('\n');
    const start = cleaned.indexOf('[');
    const end = cleaned.lastIndexOf(']');
    if (start === -1 || end === -1 || end <= start) return null;
    const jsonStr = cleaned.substring(start, end + 1);
    try {
      return JSON.parse(jsonStr);
    } catch (err) {
      console.error('Failed JSON parse after cleaning:', err.message, jsonStr.slice(0, 200));
      return null;
    }
  }

  // ChatGPT chat logic
  let chatHistory = [];
  let fullDisasmForChat = '';
  const chatArea = document.getElementById('chat-area');
  const chatInput = document.getElementById('chat-input');
  const chatSendBtn = document.getElementById('chat-send-btn');

  function renderChat() {
    chatArea.innerHTML = chatHistory.map(msg => {
      if (msg.role === 'user') {
        return `<div style="color:#0ff;margin-bottom:8px;white-space:pre-line;"><b>You:</b> ${escapeHtml(msg.content)}</div>`;
      } else {
        // Try to render markdown/code blocks for assistant
        return `<div style="color:#fff;margin-bottom:16px;white-space:pre-line;"><b>ChatGPT:</b> ${renderMarkdown(msg.content)}</div>`;
      }
    }).join('');
    chatArea.scrollTop = chatArea.scrollHeight;
  }

  // Helper to escape HTML
  function escapeHtml(text) {
    return text.replace(/[&<>]/g, tag => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[tag]));
  }

  // Basic markdown/code block rendering for assistant output
  function renderMarkdown(text) {
    // Code blocks: ```...```
    text = text.replace(/```([\s\S]*?)```/g, (m, code) => `<pre style="background:#222;color:#0f0;padding:8px;border-radius:4px;overflow-x:auto;white-space:pre;">${escapeHtml(code)}</pre>`);
    // Inline code: `...`
    text = text.replace(/`([^`]+)`/g, (m, code) => `<code style="background:#222;color:#0f0;padding:2px 4px;border-radius:3px;">${escapeHtml(code)}</code>`);
    // Bold: **...**
    text = text.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
    // Italic: *...*
    text = text.replace(/\*([^*]+)\*/g, '<i>$1</i>');
    // Line breaks
    text = text.replace(/\n/g, '<br>');
    return text;
  }

  async function sendChatMessage() {
    const userMsg = chatInput.value.trim();
    if (!userMsg) return;
    chatInput.value = '';
    chatHistory.push({ role: 'user', content: userMsg });
    renderChat();
    chatArea.innerHTML += '<div style="color:#888;">ChatGPT is typing...</div>';
    chatArea.scrollTop = chatArea.scrollHeight;
    try {
      // Loading indicator removed for chat
      if (!openaiConfig.openai_api_key || openaiConfig.openai_api_key.startsWith('sk-...')) {
        throw new Error('OpenAI API key not set in config.json');
      }
      // Compose messages: system prompt with full disasm only when sending
      const messages = [
        { role: 'system', content: `You are an expert reverse engineer. The following is the full binary disassembly for context:\n\n${fullDisasmForChat}\n\nAnswer the user's questions about this binary. Be concise and technical.` },
        ...chatHistory
      ];
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + openaiConfig.openai_api_key
        },
        body: JSON.stringify({
          model: openaiConfig.openai_model,
          messages,
          max_tokens: 1024,
          temperature: 0.2
        })
      });
      if (!response.ok) throw new Error('OpenAI API error: ' + response.status);
      const data = await response.json();
      const reply = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content
        ? data.choices[0].message.content.trim()
        : 'No response.';
      chatHistory.push({ role: 'assistant', content: reply });
      renderChat();
    } catch (err) {
      chatHistory.push({ role: 'assistant', content: `Error: ${err.message}` });
      renderChat();
    } finally {
      // Removed loading indicator for chat
    }
  }

  if (chatSendBtn && chatInput) {
    chatSendBtn.addEventListener('click', sendChatMessage);
    chatInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') sendChatMessage();
    });
  }

  // When loading symbols, store the full disassembly for chat context
  // (do not send to chat until user sends a message)
  async function loadSymbols() {
    try {
      // Clear the symbol tree placeholder text
      symbolTreeDiv.innerHTML = '';
      showLoading('Analyzing binary...');
      // First do deep analysis with AA and apply relocations
      const initRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          'e anal.autoname=true',
          'e anal.hasnext=true',
          'e anal.jmp.tbl=true',
          'e anal.pushret=true',
          'aei',                    // Initialize ESIL
          'aeim',                   // Initialize ESIL memory
          'aeip',                   // Initialize ESIL program counter
          'aaaa',                   // Most thorough analysis
          'aac',                    // Analyze function calls
          'aar',                    // Analyze data references
          'aap',                    // Analyze function preludes
          'aan',                    // Analyze function names
          'aas',                    // Analyze function signatures
          '/a call',                // Find all call instructions
          '/a jmp',                 // Find all jump instructions  
          'af @@ sym.*',            // Analyze functions at all symbols
          'af @@ fcn.*',            // Analyze at function symbols
          'af @@ entry*'            // Analyze at entry points
        ].join(';')
      ]);

      // Get entry point info
      const entryRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'ie'                      // Get entry points
        ].join(';')
      ]);

      // Parse entry point address
      const entryMatch = entryRes.output.match(/vaddr=(0x[0-9a-fA-F]+)/);
      const entryAddr = entryMatch ? entryMatch[1] : '0x08049000';

      // Analyze entry point specifically
      await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          `s ${entryAddr}`,         // Seek to entry point
          'af',                     // Analyze function
          'afn entry'              // Name it entry
        ].join(';')
      ]);

      // Get entry point disassembly
      const entryDisasmRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          'e scr.color=false',
          'e asm.bytes=true',
          'e asm.lines=false',
          'e asm.flags=true',
          'e asm.xrefs=true',
          'e asm.comments=true',
          'e asm.offset=true',
          `s ${entryAddr}`,
          'pd 64'                   // Print 64 instructions from entry point
        ].join(';')
      ]);

      // Display entry point disassembly
      listingPanel.style.overflow = 'auto';
      listingPanel.style.height = '';
      listingDiv.innerHTML = formatDisassembly(entryDisasmRes.output);

      // Try to find main by looking at cross-references from entry
      const xrefsRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          `s ${entryAddr}`,
          'axt'                     // Show cross-references
        ].join(';')
      ]);

      // DIAGNOSTIC: Let's see what radare2 can actually detect
      console.log('=== DIAGNOSTIC PHASE ===');
      
      const diagnosticRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          'i',                      // Basic binary info
          'ie',                     // Entry points
          'iE',                     // Exports
          'is',                     // Symbols (text format)
          'ii',                     // Imports
          'iS',                     // Sections
          'afl',                    // Functions (text format)
          'aa',                     // Basic analysis
          'afl'                     // Functions after basic analysis
        ].join(';')
      ]);
      
      console.log('=== DIAGNOSTIC OUTPUT ===');
      console.log(diagnosticRes.output);
      console.log('=== END DIAGNOSTIC ===');

      // STEP 1: Run thorough analysis (output ignored)
      await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          'e anal.autoname=true',
          'e anal.hasnext=true',
          'e anal.jmp.tbl=true',
          'e anal.pushret=true',
          'aaaa'                    // Comprehensive analysis
        ].join(';')
      ]);

      // STEP 2: Fetch functions in pure JSON (no other commands to contaminate output)
      const funcsRes = await radare2Request([
        '-qc',
        [
          'e scr.color=false',
          'aflj'                    // List functions in JSON format only
        ].join(';')
      ]);

      console.log('Pure aflj JSON output:', funcsRes.output);
      
      // Try to parse JSON first
      let jsonFunctions = [];
      try {
        const jsonData = parseJsonArray(funcsRes.output);
        console.log('Successfully parsed JSON, type:', typeof jsonData, 'isArray:', Array.isArray(jsonData));
        console.log('JSON data:', jsonData);
        
        if (Array.isArray(jsonData)) {
          console.log(`Processing ${jsonData.length} JSON function entries`);
          jsonFunctions = jsonData.map(func => {
            console.log('Processing function entry:', func);
            const result = {
              offset: `0x${func.offset.toString(16)}`,
              name: (func.name || '').replace('sym.', '').replace('fcn.', '').replace('entry0', 'entry'),
              size: func.size ? func.size.toString() : ''
            };
            console.log('Mapped to:', result);
            return result;
          }).filter(f => {
            const valid = f.name && f.offset;
            console.log('Function valid?', valid, f);
            return valid;
          });
          console.log('Final JSON functions:', jsonFunctions);
        } else {
          console.log('JSON data is not an array, it is:', jsonData);
        }
      } catch (e) {
        console.log('Failed to parse JSON, error:', e.message);
        console.log('Raw output that failed to parse:', JSON.stringify(funcsRes.output));
      }

      // Fallback to regular afl if JSON parsing failed
      if (jsonFunctions.length === 0) {
        console.log('JSON functions is empty, trying fallback text parsing...');
        const textFuncsRes = await radare2Request([
          '-qc',
          [
            'e bin.relocs.apply=true',
            'e bin.cache=true',
            'e io.cache=true',
            'afl'                     // List functions in text format
          ].join(';')
        ]);
        
        console.log('Fallback afl output:', textFuncsRes.output);
        console.log('Fallback afl output length:', textFuncsRes.output.length);
        
        // Parse text output
        const lines = textFuncsRes.output.replace(/\x1b\[[0-9;]*m/g, '').split('\n').filter(line => line.trim());
        console.log(`Processing ${lines.length} text function lines`);
        
        jsonFunctions = lines.map(line => {
            const trimmed = line.trim();
            console.log('Parsing fallback line:', trimmed);
            
            const tokens = trimmed.split(/\s+/);
            console.log('Tokens:', tokens);
            
            // Attempt to find an address token first
            let addrTok = tokens.find(tok => /^0x[0-9a-fA-F]+$/.test(tok));
            let nameTok;
            
            // If no explicit 0x address, maybe the name token contains the address (e.g., fcn.000005d8)
            if (!addrTok) {
              const candidate = tokens.find(tok => /(sym\.|fcn\.|sub_?)[0-9a-fA-F]+/.test(tok));
              if (candidate) {
                // Extract hex address part from candidate
                const addrMatch = candidate.match(/[0-9a-fA-F]{4,}/);
                if (addrMatch) {
                  addrTok = `0x${addrMatch[0]}`;
                  nameTok = candidate;
                }
              }
            }
            
            // If still no address, skip
            if (!addrTok) {
              console.log('No address found, skipping line');
              return null;
            }
            
            // Determine function name
            if (!nameTok) {
              // Prefer a token that looks like a symbol name
              nameTok = tokens.find(tok => tok.startsWith('sym.') || tok.startsWith('fcn.') || tok.startsWith('sub.') || tok === 'main' || tok === '_start' || tok === 'entry0');
            }
            
            if (!nameTok) {
              // Fallback to last token if it's non-numeric
              const lastTok = tokens[tokens.length - 1];
              if (!/^\d+$/.test(lastTok)) {
                nameTok = lastTok;
              } else {
                // If last token is numeric (e.g., size), try the first token
                const firstTok = tokens[0];
                if (!/^\d+$/.test(firstTok)) {
                  nameTok = firstTok;
                }
              }
            }
            
            if (!nameTok) {
              console.log('No suitable name found, skipping line');
              return null;
            }
            
            if (/^\d+$/.test(nameTok)) {
              console.log('Name is purely numeric, skipping');
              return null;
            }
 
            let name = nameTok;
            name = name.replace('sym.', '').replace('fcn.', '').replace('sub.', '').replace('entry0', 'entry');
            
            const result = {
              offset: addrTok,
              name,
              size: ''
            };
            console.log('Text parsed function:', result);
            return result;
          })
          .filter(func => {
            const valid = func && func.name && func.offset;
            console.log('Text function valid?', valid, func);
            return valid;
          });
          
        console.log('Final text parsed functions:', jsonFunctions);
      }

      // Also try alternative method - get symbols and exports that might be functions
      const symbolsRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'isj'                     // List symbols in JSON format
        ].join(';')
      ]);
      
      console.log('Raw symbols JSON output:', symbolsRes.output); // Debug symbols

      // Parse symbols to find additional functions
      let symbolFunctions = [];
      try {
        const symbolData = parseJsonArray(symbolsRes.output);
        console.log('Successfully parsed symbols JSON, length:', symbolData ? symbolData.length : 'null');
        console.log('First few symbols:', symbolData ? symbolData.slice(0, 5) : 'none');
        
        if (Array.isArray(symbolData)) {
          console.log(`Processing ${symbolData.length} symbol entries for functions`);
          
          // Only keep symbols that radare2 itself classifies as real functions. This prevents
          // non-function symbols (e.g., __abi_tag, section markers) from showing up in the
          // "Functions" list and avoids "Cannot find function" errors later when selecting
          // them from the UI.
          const filteredSymbols = symbolData.filter(sym => {
            const isFunc = sym.type === 'FUNC';
            if (!isFunc) return false;
            console.log('Accepted function symbol:', sym);
            return true;
          });
          
          console.log(`Filtered to ${filteredSymbols.length} potential function symbols`);
          
          symbolFunctions = filteredSymbols
            .map(sym => {
              const result = {
                offset: `0x${sym.vaddr.toString(16)}`,
                name: (sym.name || '').replace('sym.', '').replace('fcn.', '').replace('entry0', 'entry'),
                size: sym.size ? sym.size.toString() : ''
              };
              console.log('Symbol mapped to function:', result);
              return result;
            })
            .filter(f => {
              const valid = f.name && f.offset && f.name !== '';
              console.log('Symbol function valid?', valid, f);
              return valid;
            });
          console.log('Final symbol functions:', symbolFunctions);
        }
      } catch (e) {
        console.log('Failed to parse symbols JSON, error:', e.message);
        console.log('Raw symbols output that failed:', JSON.stringify(symbolsRes.output));
      }

      // Merge functions and symbols, removing duplicates
      functions = [...jsonFunctions];
      console.log(`Starting with ${functions.length} functions from main analysis`);
      
      symbolFunctions.forEach(symFunc => {
        const existing = functions.find(f => 
          f.offset === symFunc.offset || f.name === symFunc.name
        );
        if (!existing) {
          console.log('Adding new function from symbols:', symFunc);
          functions.push(symFunc);
        } else {
          console.log('Skipping duplicate function:', symFunc, 'existing:', existing);
        }
      });
      
      console.log(`Final merged function count: ${functions.length}`);
      console.log(`Found ${functions.length} functions:`, functions.map(f => `${f.name}@${f.offset}`));

      // BACKUP: If we still have very few functions, try direct pattern matching
      if (functions.length <= 2) {
        console.log('=== BACKUP FUNCTION DISCOVERY ===');
        
        const backupRes = await radare2Request([
          '-qc',
          [
            'e bin.relocs.apply=true',
            'e bin.cache=true',
            '/c push ebp',            // Find x86 function prologs
            '/c push rbp',            // Find x64 function prologs  
            '/c sub esp',             // Find stack setup
            '/c sub rsp',             // Find stack setup (x64)
            'aa',                     // Simple analysis
            'af @@ fcn.*',            // Analyze at function locations
            'af @@ sym.*',            // Analyze at symbol locations
            'afl'                     // List functions
          ].join(';')
        ]);
        
        console.log('Backup discovery output:', backupRes.output);
        
        // Parse backup results
        const backupLines = backupRes.output.split('\n').filter(line => 
          line.trim() && 
          (line.includes('0x') || line.includes('fcn.') || line.includes('sym.'))
        );
        
        console.log('Backup lines:', backupLines);
        
        backupLines.forEach(line => {
          const trimmed = line.trim();
          if (trimmed.match(/^0x[0-9a-fA-F]+/)) {
            const tokens = trimmed.split(/\s+/);
            const offset = tokens[0];
            let name = tokens[tokens.length - 1] || `fcn_${offset}`;
            name = name.replace('sym.', '').replace('fcn.', '');
            
            const existing = functions.find(f => f.offset === offset || f.name === name);
            if (!existing && offset && name) {
              console.log('Adding backup function:', { offset, name });
              functions.push({ offset, name, size: '' });
            }
          }
        });
        
        console.log(`After backup discovery: ${functions.length} functions`);
      }

      // LAST RESORT: Manual disassembly parsing if we still have very few functions
      if (functions.length <= 2) {
        console.log('=== MANUAL DISASSEMBLY PARSING ===');
        
        const disasmRes = await radare2Request([
          '-qc',
          [
            'e bin.relocs.apply=true',
            'e bin.cache=true',
            'e io.cache=true',
            's 0x0',                  // Seek to start
            'pd 1000'                 // Get first 1000 instructions
          ].join(';')
        ]);
        
        console.log('Manual disassembly for parsing:', disasmRes.output.substring(0, 500) + '...');
        
        const disasmLines = disasmRes.output.split('\n');
        const manualFunctions = [];
        
        disasmLines.forEach(line => {
          const trimmed = line.trim();
          
          // Look for function-like patterns in disassembly
          if (trimmed.includes('(fcn)') || 
              trimmed.includes('main') ||
              trimmed.includes('_start') ||
              trimmed.includes('entry') ||
              trimmed.match(/^\/\s+\d+:\s+fcn\./)) {
            
            const addressMatch = trimmed.match(/0x[0-9a-fA-F]+/);
            const nameMatch = trimmed.match(/fcn\.([^\s\)]+)|sym\.([^\s\)]+)|(\w+)/);
            
            if (addressMatch) {
              const offset = addressMatch[0];
              let name = 'unknown';
              
              if (nameMatch) {
                name = nameMatch[1] || nameMatch[2] || nameMatch[3] || 'unknown';
                name = name.replace('sym.', '').replace('fcn.', '');
              }
              
              const existing = functions.find(f => f.offset === offset);
              if (!existing && offset && name && name !== 'unknown') {
                console.log('Adding manual function:', { offset, name });
                manualFunctions.push({ offset, name, size: '' });
              }
            }
          }
        });
        
        functions.push(...manualFunctions);
        console.log(`After manual parsing: ${functions.length} functions`);
      }

      // Add entry point if not in functions list
      if (!functions.find(f => f.offset === entryAddr)) {
        functions.unshift({
          offset: entryAddr,
          name: 'entry',
          size: ''
        });
      }

      // Sort functions to show entry and main first
      functions.sort((a, b) => {
        const importantFuncs = ['entry', 'main'];
        const aIndex = importantFuncs.indexOf(a.name.toLowerCase());
        const bIndex = importantFuncs.indexOf(b.name.toLowerCase());
        
        if (aIndex !== -1 && bIndex !== -1) return aIndex - bIndex;
        if (aIndex !== -1) return -1;
        if (bIndex !== -1) return 1;
        return a.name.localeCompare(b.name);
      });

      console.log('=== FINAL FUNCTION LIST ===');
      console.log(`Total functions to display: ${functions.length}`);
      functions.forEach((func, index) => {
        console.log(`${index + 1}. ${func.name} @ ${func.offset} (size: ${func.size})`);
      });
      console.log('=== END FINAL LIST ===');

      // Get imports
      const importsRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'ii'                      // List imports
        ].join(';')
      ]);

      const imports = importsRes.output.split('\n')
        .filter(line => line.trim())
        .map(line => {
          const tokens = line.trim().split(/\s+/);
          // Find first 0x address token if present
          const addrTok = tokens.find(tok => /^0x[0-9a-fA-F]+$/.test(tok));
          const nameTok = tokens[tokens.length - 1];
          if (!addrTok) {
            return { import: nameTok, offset: '' }; // will handle later
          }
          return {
            import: nameTok,
            offset: addrTok
          };
        });

      // Get exports
      const exportsRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'iE'                      // List exports
        ].join(';')
      ]);

      const exports = exportsRes.output.split('\n')
        .filter(line => line.trim())
        .map(line => {
          const tokens = line.trim().split(/\s+/);
          // Find first 0x address token if present
          const addrTok = tokens.find(tok => /^0x[0-9a-fA-F]+$/.test(tok));
          const nameTok = tokens[tokens.length - 1];
          if (!addrTok) {
            return { export: nameTok, offset: '' }; // will handle later
          }
          return {
            export: nameTok,
            offset: addrTok
          };
        })
        .filter(exp => exp && exp.export); // Filter out invalid exports

      // Get strings
      const stringsRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          'iz'                      // List strings in data sections
        ].join(';')
      ]);

      const strings = stringsRes.output.split('\n')
        .filter(line => line.trim())
        .map(line => {
          // Find the last occurrence of 'ascii ' or 'wide ' in the line
          const stringStart = Math.max(line.lastIndexOf('ascii '), line.lastIndexOf('wide '));
          if (stringStart === -1) return null;
          
          // Extract just the string content after 'ascii ' or 'wide '
          const content = line.substring(stringStart).split(' ').slice(1).join(' ');
          
          return {
            offset: line.split(' ')[0],
            string: content
          };
        })
        .filter(s => s && s.string); // Only keep valid strings with content

      // First get the .text section info
      const sectionRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e io.cache=true',
          'iS'                      // Get section information
        ].join(';')
      ]);

      // Parse the section info to find .text
      const textSection = sectionRes.output.split('\n')
        .find(line => line.includes('.text'));
      
      if (!textSection) {
        throw new Error('Could not find .text section');
      }

      // Extract vaddr and sz using regex to handle different output formats
      let vaddrMatch = textSection.match(/vaddr=0x[0-9a-fA-F]+/);
      let sizeMatch = textSection.match(/sz=0x[0-9a-fA-F]+/);

      let vaddr;
      let size;

      if (vaddrMatch && sizeMatch) {
        vaddr = vaddrMatch[0].split('=')[1];
        size = parseInt(sizeMatch[0].split('=')[1], 16);
      } else {
        // Fallback: split by whitespace
        const partsSec = textSection.trim().split(/\s+/);
        // Attempt to find hex values in each token
        vaddr = partsSec.find(tok => /^0x[0-9a-fA-F]+$/.test(tok)) || '0x0';
        const sizeTok = partsSec.find(tok => /^0x[0-9a-fA-F]+$/.test(tok) && tok !== vaddr);
        size = sizeTok ? parseInt(sizeTok, 16) : 4096; // default if not found
      }
 
      // Now get the complete disassembly (separate clean call to avoid analysis logs)
      const fullDisasmRes = await radare2Request([
        '-qc',
        [
          'e bin.relocs.apply=true',
          'e bin.cache=true',
          'e scr.color=false',
          'e asm.bytes=true',
          'e asm.lines=false',
          'e asm.flags=true',
          'e asm.xrefs=true',
          'e asm.comments=true',
          'e asm.offset=true',
          'e anal.hasnext=true',
          `s ${vaddr}`,           // Seek to .text start
          `pd ${size}`            // Disassemble entire .text section (size in bytes -> instruction count may be larger, adjust if needed)
        ].join(';')
      ]);

      const formattedFullDisasm = formatDisassembly(fullDisasmRes.output);
      fullDisasmHTML = formattedFullDisasm;
      fullDisasmForChat = fullDisasmRes.output;

      // Add "Full Disassembly" section at the top
      addSymbolSection('Disassembly', [{
        name: 'Full Binary Disassembly',
        type: 'disasm',
        content: fullDisasmRes.output
      }], 'disasm');

      addSymbolSection('Functions', functions, 'functions');
      if (imports.length > 0) addSymbolSection('Imports', imports, 'imports');
      if (exports.length > 0) addSymbolSection('Exports', exports, 'exports');
      if (strings.length > 0) addSymbolSection('Strings', strings, 'strings');
    } catch (error) {
      throw new Error(`Failed to load symbols: ${error.message}`);
    } finally {
      hideLoading();
    }
  }

  let openaiConfig = {
    openai_api_key: '',
    openai_model: 'gpt-4o',
    openai_prompt: 'You are an expert reverse engineer. Convert the following assembly code into equivalent Python code. Only output the Python code, no explanations.'
  };

  // Load config.json at startup (first look for an external file beside the executable,
  // then fall back to the one packaged next to this script)
  (function loadConfig() {
    try {
      const fs = require('fs');
      const path = require('path');

      const candidatePaths = [];

      // When packaged: <installDir>/resources/app.asar/... (this file) → look one level up
      if (process.resourcesPath) {
        candidatePaths.push(path.join(process.resourcesPath, '..', 'config.json'));
      }

      // Development fallback: the file sitting next to index.html/renderer.js
      candidatePaths.push(path.join(__dirname, 'config.json'));

      for (const p of candidatePaths) {
        if (fs.existsSync(p)) {
          const raw = fs.readFileSync(p, 'utf-8');
          openaiConfig = JSON.parse(raw);
          console.log('[config] Loaded config from', p);
          return;
        }
      }
      console.warn('[config] config.json not found in any known location');
    } catch (err) {
      console.error('[config] Failed to load config.json:', err);
    }
  })();

  function addSymbolSection(title, items, section) {
    if (!items || items.length === 0) return;

    console.log(`Adding ${title} section:`, items);
    // Create collapsible subsection inside Symbol Tree
    const secDetails = document.createElement('details');
    secDetails.className = 'symbol-subsection';
    secDetails.open = false; // collapsed by default; set to true to expand by default

    const summary = document.createElement('summary');
    summary.textContent = title;
    secDetails.appendChild(summary);

    // --- Add Analyze to Python button for Disassembly section ---
    if (section === 'disasm') {
      const analyzeBtn = document.createElement('button');
      analyzeBtn.textContent = 'Analyze Full Disassembly to Python';
      analyzeBtn.style.margin = '8px 0';
      analyzeBtn.style.background = '#333';
      analyzeBtn.style.color = '#0ff';
      analyzeBtn.style.border = 'none';
      analyzeBtn.style.borderRadius = '3px';
      analyzeBtn.style.padding = '6px 16px';
      analyzeBtn.style.fontSize = '1em';
      analyzeBtn.style.cursor = 'pointer';
      analyzeBtn.addEventListener('mouseenter', () => {
        analyzeBtn.style.background = '#444';
      });
      analyzeBtn.addEventListener('mouseleave', () => {
        analyzeBtn.style.background = '#333';
      });
      analyzeBtn.onclick = async () => {
        const disasmText = items[0].content;
        listingDiv.innerHTML = '<div style="padding:1em">Analyzing disassembly to Python code... <span class="spinner-small"></span></div>';
        try {
          // Removed loading overlay for Analyse to Python
          if (!openaiConfig.openai_api_key || openaiConfig.openai_api_key.startsWith('sk-...')) {
            throw new Error('OpenAI API key not set in config.json');
          }
          const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer ' + openaiConfig.openai_api_key
            },
            body: JSON.stringify({
              model: openaiConfig.openai_model,
              messages: [
                { role: 'system', content: openaiConfig.openai_prompt },
                { role: 'user', content: disasmText }
              ],
              max_tokens: 2048,
              temperature: 0.2
            })
          });
          if (!response.ok) throw new Error('OpenAI API error: ' + response.status);
          const data = await response.json();
          const pythonCode = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content
            ? data.choices[0].message.content.trim()
            : 'No Python code returned.';
          listingPanel.style.overflow = 'auto';
          listingPanel.style.height = '';
          listingDiv.innerHTML = `<pre class="python-listing" style="background:#222;color:#fff;padding:1em;overflow:auto;max-height:60vh;">${pythonCode.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`;
        } catch (err) {
          listingDiv.innerHTML = `<div style="color:red">Error: ${err.message}</div>`;
        } finally {
          // No loading overlay to hide for Analyse to Python
        }
      };
      secDetails.appendChild(analyzeBtn);
    }
    // --- End button addition ---

    const ul = document.createElement('ul');
    ul.className = 'symbol-list';
    items.forEach(item => {
      const li = document.createElement('li');
      // For strings, show a preview of the string content
      if (section === 'strings') {
        const preview = item.string.length > 30 ? item.string.substring(0, 27) + '...' : item.string;
        li.textContent = preview;
        li.title = item.string; // Show full string on hover
      } else {
        li.textContent = item.name || item.import || item.export || item.ordinal || item;
        li.title = li.textContent;
      }
      li.addEventListener('click', () => onSymbolClick(section, item));
      ul.appendChild(li);
    });
    secDetails.appendChild(ul);
    symbolTreeDiv.appendChild(secDetails);
  }

  async function onSymbolClick(section, item) {
    try {
      if (section === 'disasm') {
        // Display full disassembly
        listingPanel.style.overflow = 'auto';
        listingPanel.style.height = '';
        listingDiv.innerHTML = formatDisassembly(item.content);
      } else if (section === 'functions') {
        // Ensure we have a valid hex address
        const offset = item.offset.startsWith('0x') ? item.offset : `0x${item.offset}`;
        
        // First try to analyze the function at the offset
        const analyzeRes = await radare2Request([
          '-qc',
          [
            'e bin.relocs.apply=true',
            'e bin.cache=true',
            'e io.cache=true',
            `s ${offset}`,         // Seek to offset
            'af',                  // Analyze function
            'afr'                  // Analyze references
          ].join(';')
        ]);

        // Get function info
        const infoRes = await radare2Request([
          '-qc',
          [
            'e bin.relocs.apply=true',
            'e bin.cache=true',
            'e io.cache=true',
            `afi ${offset}`        // Get function info by offset instead of name
          ].join(';')
        ]);
        // paramsDiv.innerHTML = formatFunctionInfo(infoRes.output); // Removed paramsDiv

        // Get disassembly
        const disasmRes = await radare2Request([
          '-qc',
          [
            'e bin.relocs.apply=true',
            'e bin.cache=true',
            'e io.cache=true',
            'e scr.color=false',
            'e asm.bytes=true',
            'e asm.lines=false',
            'e asm.flags=true',
            'e asm.xrefs=true',
            'e asm.comments=true',
            'e asm.offset=true',
            'e asm.functions=false',
            'e asm.section=false',
            `s ${offset}`,
            'pdf'                  // Print disassembly of function
          ].join(';')
        ]);
        
        console.log('Raw disassembly:', disasmRes.output);
        
        if (disasmRes.output.includes("Cannot find function")) {
          // If can't find function, try basic disassembly
          const altDisasmRes = await radare2Request([
            '-qc',
            [
              'e bin.relocs.apply=true',
              'e bin.cache=true',
              'e io.cache=true',
              'e scr.color=false',
              'e asm.bytes=true',
              'e asm.lines=false',
              'e asm.flags=true',
              'e asm.xrefs=true',
              'e asm.comments=true',
              'e asm.offset=true',
              `s ${offset}`,
              'af;pdf'            // Analyze function and print disassembly
            ].join(';')
          ]);
          listingDiv.innerHTML = formatDisassembly(altDisasmRes.output);
        } else {
          listingDiv.innerHTML = formatDisassembly(disasmRes.output);
        }
      } else if (section === 'strings') {
        const stringContent = item.string;

        // Show full disassembly and highlight the string
        listingDiv.innerHTML = fullDisasmHTML || formatDisassembly(item.content || '');
        // paramsDiv.innerHTML = `<div class="string-info"><span class="r2-section">String:</span> "${stringContent}"</div>`; // Removed paramsDiv

        // Reset filter and perform search highlight
        if (filterToggle) filterToggle.checked = false;
        searchInput.value = stringContent;
        clearHighlights();
        highlightTerm(stringContent);
        const first = listingDiv.querySelector('.search-highlight');
        if (first) {
          first.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      } else if (section === 'imports' || section === 'exports') {
        const symbolName = item.import || item.export || '';
        const offset = item.offset && item.offset.startsWith('0x') ? item.offset : '';

        // Attempt to gather info: xrefs and small disasm around PLT/GOT
        let display = `<div class="symbol-info">`;
        display += `<div><span class="r2-section">Symbol:</span> ${symbolName}</div>`;
        if (offset) {
          display += `<div><span class="r2-section">Address:</span> ${offset}</div>`;

          try {
            const [disasmRes, xrefsRes] = await Promise.all([
              radare2Request([
                '-qc',
                [
                  'e bin.relocs.apply=true',
                  'e bin.cache=true',
                  'e io.cache=true',
                  'e scr.color=false',
                  'e asm.bytes=true',
                  'e asm.lines=false',
                  'e asm.flags=true',
                  'e asm.comments=true',
                  'e asm.offset=true',
                  `s ${offset}`,
                  'pd 10'
                ].join(';')
              ]),
              radare2Request([
                '-qc',
                [
                  'e bin.relocs.apply=true',
                  'e bin.cache=true',
                  'e io.cache=true',
                  `s ${offset}`,
                  'axt'
                ].join(';')
              ])
            ]);

            const xrefsClean = cleanRadareOutput(xrefsRes.output);
            if (xrefsClean.trim()) {
              display += `<div><span class="r2-section">Xrefs:</span><pre>${xrefsClean}</pre></div>`;
            }
            display += `<div class="symbol-context"><span class="r2-section">Context:</span></div>`;
            display += formatDisassembly(disasmRes.output);
          } catch (err) {
            console.error('Error fetching import info:', err);
          }
        }
        display += '</div>';
        listingDiv.innerHTML = display;
        // paramsDiv.textContent = ''; // Removed paramsDiv
      } else {
        // Fallback display
        listingDiv.textContent = JSON.stringify(item, null, 2);
        // paramsDiv.textContent = ''; // Removed paramsDiv
      }
    } catch (error) {
      listingDiv.textContent = `Error: ${error.message}`;
      console.error('Error in onSymbolClick:', error);
    }
  }

  function formatFunctionInfo(info) {
    return info.split('\n')
      .map(line => {
        line = line
          .replace(/^(name|size|regs|args|vars):/i, '<span class="r2-section">$1:</span>')
          .replace(/0x[0-9a-f]+/gi, '<span class="r2-offset">$&</span>')
          .replace(/"[^"]+"/g, '<span class="r2-symbol">$&</span>');
        return `<div class="r2-line">${line}</div>`;
      })
      .join('');
  }

  // --- Resizer logic ---
  // Vertical resizer: sidebar/main width
  const verticalResizer = document.getElementById('vertical-resizer');
  const sidebar = document.getElementById('sidebar');
  const main = document.getElementById('main');
  let isResizingVert = false;
  verticalResizer.addEventListener('mousedown', function(e) {
    isResizingVert = true;
    document.body.style.cursor = 'ew-resize';
  });
  document.addEventListener('mousemove', function(e) {
    if (!isResizingVert) return;
    const minSidebar = 120;
    const maxSidebar = 600;
    let newWidth = e.clientX;
    if (newWidth < minSidebar) newWidth = minSidebar;
    if (newWidth > maxSidebar) newWidth = maxSidebar;
    sidebar.style.width = newWidth + 'px';
  });
  document.addEventListener('mouseup', function(e) {
    if (isResizingVert) {
      isResizingVert = false;
      document.body.style.cursor = '';
    }
  });

  // Horizontal resizer: listing/chat height
  const horizontalResizer = document.getElementById('horizontal-resizer');
  const listingPanel = document.getElementById('listing-panel');
  const chatPanel = document.getElementById('chat-panel');
  let isResizingHorz = false;
  let startY = 0;
  let startListingHeight = 0;
  let startChatHeight = 0;
  horizontalResizer.addEventListener('mousedown', function(e) {
    isResizingHorz = true;
    startY = e.clientY;
    startListingHeight = listingPanel.offsetHeight;
    startChatHeight = chatPanel.offsetHeight;
    document.body.style.cursor = 'ns-resize';
    e.preventDefault();
  });
  document.addEventListener('mousemove', function(e) {
    if (!isResizingHorz) return;
    const dy = e.clientY - startY;
    let newListingHeight = startListingHeight + dy;
    let newChatHeight = startChatHeight - dy;
    if (newListingHeight < 60) newListingHeight = 60;
    if (newChatHeight < 60) newChatHeight = 60;
    listingPanel.style.height = newListingHeight + 'px';
    chatPanel.style.height = newChatHeight + 'px';
    chatPanel.querySelector('#chat-area').style.height = (newChatHeight - 60) + 'px';
  });
  document.addEventListener('mouseup', function(e) {
    if (isResizingHorz) {
      isResizingHorz = false;
      document.body.style.cursor = '';
    }
  });
}); 