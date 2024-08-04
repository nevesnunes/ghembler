require.config({ paths: { vs: '../node_modules/monaco-editor/min/vs' } });

require(['vs/editor/editor.main'], function () {

    //
    // Constants
    //

    const KEY_ASM = 'asm';
    const KEY_BYTES = 'bytes';

    const LANGUAGE_EDITOR = 'langEditor';
    const LANGUAGE_BYTES = 'langBytes';

    const OWNER_EDITOR = 'ownerEditor';
    const OWNER_BYTES = 'ownerBytes';

    const MAX = 99999;
    const INVALID_LINE = -1;
    const UNKNOWN_BYTES = '??';

    //
    // Helper methods
    //

    const loadAssembly = () => {
        let storedAssembly = localStorage.getItem(KEY_ASM);
        if (storedAssembly) {
            window.instanceEditor.setValue(storedAssembly);
        }
    }

    const storeAssembly = () => {
        localStorage.setItem(KEY_ASM, window.instanceEditor.getModel().getLinesContent().join('\n'));
    }

    const hasLabel = (line) => {
        for (const tok of line.split(/[^\w]/)) {
            for (const lbl of knownLabels) {
                if (tok.includes(lbl)) {
                    return true;
                }
            }
        }
        return false;
    }

    const isDirective = (line) => {
        return /^\s*\.[0-9a-zA-Z]+:/.test(line);
    }

    const parseByteDirective = (line) => {
        return line.match(/^\s*\.byte:\s*((0x)?[0-9a-fA-F]+)\s*$/);
    }

    const parseFillDirective = (line) => {
        return line.match(/^\s*\.fill:\s*((0x)?[0-9a-fA-F]+)\s*,\s*((0x)?[0-9a-fA-F]+)\s*$/);
    }

    const parseLabelDirective = (line) => {
        return line.match(/^\s*\.lbl:\s*(\w+)\s*$/);
    }

    const parseOriginDirective = (line) => {
        return line.match(/^\s*\.org:\s*((0x)?[0-9a-fA-F]+)\s*$/);
    }

    const isValidHexString = (hexString) => {
        const trimmedHexString = hexString.replace(/\s/g, '');
        return trimmedHexString.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(trimmedHexString);
    };

    const isValidHexNumber = (hexString) => {
        const trimmedHexString = hexString.replace(/\s/g, '').replace(/0x/, '');
        return /^[0-9a-fA-F]+$/.test(trimmedHexString);
    };

    const fromHexStringToU8 = (hexString) =>
        Uint8Array.from(hexString.replace(/\s/g, '').match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

    const fromHexStringToPy = (hexString) =>
        Array.prototype.join.call(hexString.replace(/\s/g, '').match(/.{1,2}/g).map((byte) => `\\x${byte}`), '');

    const parseBaseOffset = () => {
        return parseInt(document.getElementById('offset-input').value.replace(/0x/, ''), 16);
    }

    const fetchCompletions = async (line) => {
        let completions = [];
        const requestConfig = {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(line)
        };
        const response = await fetch('http://localhost:18000/assemble/', requestConfig)
        if (response.ok) {
            completions = await response.json()
        } else {
            console.error(response.statusText);
        }
        return completions;
    };

    const fetchDisassembly = async (line) => {
        let completions = [];
        const requestConfig = {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(line)
        };
        const response = await fetch('http://localhost:18000/disassemble/', requestConfig)
        if (response.ok) {
            completions = await response.json()
        } else {
            console.error(response.statusText);
        }
        return completions;
    };

    const currentByteOffset = function(editorLineNumber, startLineNumber, offset) {
        const modelBytes = window.instanceBytes.getModel();
        const modelEditor = window.instanceEditor.getModel();
        for (var i = startLineNumber; i < modelBytes.getLineCount() + 1; i++) {
            if (i === editorLineNumber) {
                break;
            }
            let line = modelBytes.getLineContent(i).trimStart();
            if (!line) {
                const disassembledLine = modelEditor.getLineContent(i).trim();
                if (isDirective(disassembledLine)) {
                    let candidateOrigin = parseOriginDirective(disassembledLine);
                    if (candidateOrigin) {
                        offset = parseInt(candidateOrigin[1], 16);
                    }
                }
                continue;
            }
            if (isValidHexString(line)) {
                line.replace(/\s/g, '').match(/.{1,2}/g).map((_) => { offset++; });
            } else {
                console.error(`Invalid hex string @ ${i} = '${line}'`);
            }
        }
        return [i, offset];
    };

    const syncBytes = function() {
        (async () => {
            let baseOffset = parseBaseOffset();
            let newBytes = [];
            let emptyLines = new Set();
            let requestLines = [];
            const modelBytes = window.instanceBytes.getModel();
            const modelEditor = window.instanceEditor.getModel();
            for (let i = 1; i < modelEditor.getLineCount() + 1; i++) {
                let line = modelEditor.getLineContent(i).trim();
                if (!line) {
                    emptyLines.add(i);
                } else if (isDirective(line)) {
                    let candidateByte = parseByteDirective(line);
                    if (candidateByte) {
                        requestLines.push({
                            "address": baseOffset,
                            "data": [1, candidateByte[1]].join(","),
                            "type": "fill",
                        });
                    }
                    let candidateFill = parseFillDirective(line);
                    if (candidateFill) {
                        requestLines.push({
                            "address": baseOffset,
                            "data": [candidateFill[1], candidateFill[3]].join(","),
                            "type": "fill",
                        });
                    }
                    let candidateLabel = parseLabelDirective(line);
                    if (candidateLabel) {
                        knownLabels.add(candidateLabel[1]);
                        requestLines.push({
                            "address": baseOffset,
                            "data": candidateLabel[1],
                            "type": "label",
                        });
                    }
                    let candidateOrigin = parseOriginDirective(line);
                    if (candidateOrigin) {
                        requestLines.push({
                            "address": baseOffset,
                            "data": candidateOrigin[1],
                            "type": "origin",
                        });
                    }
                } else {
                    let previousLength = 0;
                    let previousData = '';
                    if (i == currentSyncBytesLineNumber) {
                        previousLength = currentSyncBytesLineLength;
                        previousData = currentSyncBytesLineData;

                        cache[i - 1].bytes = previousData;
                        cache[i - 1].hasPrev = true;

                        currentSyncBytesLineNumber = INVALID_LINE;
                        currentSyncBytesLineLength = 0;
                        currentSyncBytesLineData = '';
                    } else if (cache[i - 1]?.asm == modelEditor.getLineContent(i)) {
                        if (cache[i - 1]?.hasPrev) {
                            previousData = cache[i - 1]?.bytes;
                            previousLength = previousData.length;
                        } else if (i >= cacheOffsetLine && (modelBytes.getLineCount() >= i - cacheOffset)) {
                            previousData = modelBytes.getLineContent(i - cacheOffset);
                            previousLength = previousData.length;
                        } else if (modelBytes.getLineCount() >= i) {
                            previousData = modelBytes.getLineContent(i);
                            previousLength = previousData.length;
                        }
                    }
                    requestLines.push({
                        "address": baseOffset,
                        "data": line,
                        "previousLength": previousLength,
                        "previousData": previousData,
                    });
                }
            }

            let completionSet = await fetchCompletions(requestLines);

            let markers = [];
            let completionIndex = 0;
            for (let i = 1; i < modelEditor.getLineCount() + 1; i++) {
                if (emptyLines.has(i)) {
                    newBytes.push('');
                } else if (completionIndex < completionSet.length) {
                    let completions = completionSet[completionIndex];
                    let hexBytes = UNKNOWN_BYTES;
                    completions.forEach((completion) => {
                        if (completion.type === "bytes") {
                            hexBytes = completion.data;
                        } else if (completion.type === "ok") {
                            // Used by directives, display them as blank
                            hexBytes = '';
                        } else if (completion.type === "assembly_error") {
                            // x86 spams several constructor errors...
                            // console.error(completion.data);
                        } else if (completion.type === "error") {
                            markers.push({
                                startLineNumber: i,
                                endLineNumber: i,
                                startColumn: 0,
                                endColumn: MAX,
                                message: completion.data,
                                severity: monaco.MarkerSeverity.Error,
                            });
                        } else {
                            console.error(`Unknown response at line '${i}': '${JSON.stringify(completion)}'`);
                        }
                    });
                    newBytes.push(hexBytes);

                    completionIndex++;
                } else {
                    markers.push({
                        startLineNumber: i,
                        endLineNumber: i,
                        startColumn: 0,
                        endColumn: MAX,
                        message: `Line not in completion set (${completionIndex} >= ${completionSet.length})`,
                        severity: monaco.MarkerSeverity.Error,
                    });
                }
            }

            monaco.editor.setModelMarkers(window.instanceEditor.getModel(), OWNER_EDITOR, markers);

            isModelBytesSync = true;
            const position = window.instanceBytes.getPosition();
            window.instanceBytes.setValue(newBytes.join('\n'));
            window.instanceBytes.setPosition(position);

            updateCacheWithBytes(newBytes);
        })();
    };

    const updateCacheWithAssembly = function(newAssembly) {
        for (let i = 0; i < newAssembly.length; i++) {
            cache[i].asm = newAssembly[i];
        }
    };

    const updateCacheWithBytes = function(newBytes) {
        for (let i = 0; i < newBytes.length; i++) {
            cache[i].bytes = newBytes[i];
        }
    };

    const updateCacheOnChanges = function(context, model, key) {
        const modelBytes = window.instanceBytes.getModel();
        const modelEditor = window.instanceEditor.getModel();
        const lineCountBytes = modelBytes.getLineCount();
        const lineCountEditor = modelEditor.getLineCount();
        const lineCountMax = Math.max(lineCountBytes, lineCountEditor);
        const lineCount = key == KEY_ASM ? lineCountEditor : lineCountBytes;

        // FIXME: How to handle more than one change?
        const change = context.changes[0];
        const linesBefore = change.range.endLineNumber - change.range.startLineNumber;
        const linesAfter = (change.text.match(/\n/g) || []).length;
        cacheOffset = linesAfter - linesBefore;

        // Match all identical lines from the start.
        // We should have both lines before change range, and the first
        // in-range modifications that resulted in previously present lines.
        let newCache = [];
        let startIdx = 1;
        for (let i = 1; i < lineCount + 1; i++) {
            if (cache[i - 1]?.[key] != model.getLineContent(i)) {
                break;
            }
            if (i >= change.range.startLineNumber && !model.getLineContent(i)) {
                // HACK: Due to bytes being blank for directive lines, we must prevent
                // them from being added here, otherwise they will be duplicated.
                break;
            }
            newCache.push({
                asm: cache[i - 1]?.asm || modelEditor.getLineContent(i),
                bytes: cache[i - 1]?.bytes || modelBytes.getLineContent(i),
                hasPrev: cache[i - 1]?.hasPrev || false,
            });
            startIdx++;

            // Special case: If this is a blank line, and a directive is on the next one,
            // move the directive to this line. Otherwise, the directive would be lost on deleted lines.
            if (cacheOffset < 0
                    && i >= change.range.startLineNumber
                    && isDirective(cache[i]?.asm)
                    && !(newCache[i - 1]?.asm.trim())) {
                newCache[i - 1].asm = cache[i].asm;
                cache[i].asm = "";
            }
        }

        // Match all identical lines from the end.
        // We should have both lines after change range, and the last
        // in-range modifications that resulted in previously present lines.
        let i = lineCountMax;
        let asmIdx = lineCountEditor;
        let bytesIdx = lineCountBytes;
        let endNewCache = [];
        for (; i > startIdx && i >= change.range.startLineNumber; i--) {
            let keyIdx = key == KEY_ASM ? asmIdx : bytesIdx;
            if (keyIdx < 1 || cache[keyIdx - 1 - cacheOffset]?.[key] != model.getLineContent(keyIdx)) {
                break;
            }
            let asmOffset = key == KEY_ASM ? cacheOffset : 0;
            let bytesOffset = key == KEY_BYTES ? cacheOffset : 0;
            endNewCache.unshift({
                asm: cache[asmIdx - 1 - asmOffset]?.asm || modelEditor.getLineContent(asmIdx),
                bytes: cache[bytesIdx - 1 - bytesOffset]?.bytes || modelBytes.getLineContent(bytesIdx),
                hasPrev: cache[bytesIdx - 1 - bytesOffset]?.hasPrev || false,
            });
            asmIdx--;
            bytesIdx--;
        }

        // In range: Invalidate previously cached lines.
        let inRangeNewCache = [];
        for (; i >= startIdx && i >= change.range.startLineNumber; i--) {
            let keyIdx = key == KEY_ASM ? asmIdx : bytesIdx;
            if (startIdx > keyIdx) {
                break; // Already covered on match from the start.
            }
            inRangeNewCache.unshift({
                asm: (key == KEY_BYTES || asmIdx < 1) ? "" : modelEditor.getLineContent(asmIdx),
                bytes: (key == KEY_ASM || bytesIdx < 1) ? "" : modelBytes.getLineContent(bytesIdx),
                hasPrev: key == KEY_BYTES,
            });
            asmIdx--;
            bytesIdx--;
        }

        //console.log("i startIdx key asmIdx bytesIdx:", i, startIdx, key, asmIdx, bytesIdx);
        //console.log("newCache:", newCache);
        //console.log("inRangeNewCache:", inRangeNewCache);
        //console.log("endNewCache:", endNewCache);
        cache = newCache.concat(inRangeNewCache.concat(endNewCache));

        for (let i = 0; i < cache.length; i++) {
            // Special case: If this is a blank line, and a directive was set on the last one,
            // move the directive to this line. Otherwise, new instructions couldn't be set
            // before the directive without modifying the previous instruction.
            if (isDirective(cache[i - 2]?.asm) && !(cache[i - 1]?.asm.trim())) {
                cache[i - 1].asm = cache[i - 2].asm;
                cache[i - 2].asm = "";
            }
        }
    };

    const syncBytesLine = function(lineNumber, text) {
        const range = new monaco.Range(lineNumber, 0, lineNumber, MAX);
        const id = { major: 1, minor: 1 };

        // If the target editor has less lines than the target line to edit,
        // we need to prepend as many newlines as needed to match both editors
        const modelBytes = window.instanceBytes.getModel();
        let linesToAdd = lineNumber - modelBytes.getLineCount();
        while (linesToAdd > 0) {
            text = '\n' + text;
            linesToAdd--;
        }

        isModelBytesSync = true;
        const editOperation = {identifier: id, range: range, text: text, forceMoveMarkers: true};
        window.instanceBytes.executeEdits("custom-code", [ editOperation ]);
    };

    const syncAssemblyEditor = function() {
        (async () => {
            let isModelSyncBytesRequired = true;
            let baseOffset = parseBaseOffset();
            let newAssembly = [];
            let emptyLines = new Set();
            let requestLines = [];
            const modelBytes = window.instanceBytes.getModel();
            const modelEditor = window.instanceEditor.getModel();
            for (let i = 1; i < modelBytes.getLineCount() + 1; i++) {
                let cacheIdx = i - 1;
                let line = modelBytes.getLineContent(i).trim();
                if (!line) {
                    emptyLines.add(i);
                    if (cacheIdx in cache) {
                        let candidateDirective = cache[cacheIdx]?.asm;
                        if (isDirective(candidateDirective)) {
                            let candidateLabel = parseLabelDirective(candidateDirective);
                            if (candidateLabel) {
                                knownLabels.add(candidateLabel[1]);
                                requestLines.push({
                                    "address": baseOffset,
                                    "data": candidateLabel[1],
                                    "type": "label",
                                });
                            }
                            let candidateOrigin = parseOriginDirective(candidateDirective);
                            if (candidateOrigin) {
                                requestLines.push({
                                    "address": baseOffset,
                                    "data": candidateOrigin[1],
                                    "type": "origin",
                                });
                            }
                        }
                    }
                } else {
                    requestLines.push({
                        "address": baseOffset,
                        "data": line,
                        "type": "instruction",
                    });
                }
            }

            let disassemblySet = await fetchDisassembly(requestLines);

            let markers = [];
            let disassemblyIndex = 0;
            for (let i = 1; i < modelBytes.getLineCount() + 1; i++) {
                let disassemblyCandidate = "";
                if (disassemblyIndex < disassemblySet.length) {
                    disassemblyCandidate = disassemblySet[disassemblyIndex];
                }

                let cacheIdx = i - 1;
                if (emptyLines.has(i)) {
                    if (cache[cacheIdx]?.asm) {
                        // Preserve directives
                        newAssembly.push(cache[cacheIdx]?.asm);
                        disassemblyIndex++;
                    } else {
                        // Empty on both editors
                        newAssembly.push('');
                    }
                } else if (disassemblyCandidate && disassemblyCandidate.type === "ok") {
                    if (cacheIdx in cache
                            && cache[cacheIdx].asm.split(/[^\w]/)[0] == disassemblyCandidate.data.split(/[^\w]/)[0]
                            && hasLabel(cache[cacheIdx].asm)
                            && !hasLabel(disassemblyCandidate.data)) {
                        // Preserve instructions with user-defined labels
                        // if the mnemonic is the same after edits
                        newAssembly.push(cache[cacheIdx].asm);
                        disassemblyIndex++;
                    } else {
                        newAssembly.push(disassemblyCandidate.data);
                        disassemblyIndex++;
                    }
                } else if (disassemblyCandidate && disassemblyCandidate.type === "error") {
                    markers.push({
                        startLineNumber: i,
                        endLineNumber: i,
                        startColumn: 0,
                        endColumn: MAX,
                        message: disassemblyCandidate.data,
                        severity: monaco.MarkerSeverity.Error,
                    });
                } else if (disassemblyCandidate && disassemblyCandidate.type === "assembly_error") {
                    // x86 spams several constructor errors...
                    // console.error(disassemblyCandidate);
                } else if (disassemblyCandidate && disassemblyIndex >= disassemblySet.length) {
                    markers.push({
                        startLineNumber: i,
                        endLineNumber: i,
                        startColumn: 0,
                        endColumn: MAX,
                        message: `Line not in disassembly set (${disassemblyIndex} >= ${disassemblySet.length})`,
                        severity: monaco.MarkerSeverity.Error,
                    });
                } else {
                    console.error(`Unknown candidate at index '${disassemblyIndex}': '${JSON.stringify(disassemblyCandidate)}'`);
                    console.error("Request lines:", requestLines);
                    console.error("Response:", disassemblySet);
                }
            }

            monaco.editor.setModelMarkers(window.instanceEditor.getModel(), OWNER_EDITOR, markers);

            isModelEditorSync = true;
            window.instanceEditor.setValue(newAssembly.join('\n'));

            storeAssembly();
            updateCacheWithAssembly(newAssembly);

            for (let i = 1; i < modelEditor.getLineCount() + 1; i++) {
                if (modelEditor.getLineContent(i) == UNKNOWN_BYTES) {
                    isModelSyncBytesRequired = false;
                }
            }
            if (isModelSyncBytesRequired) {
                // Need to resync bytes when instruction lengths change, so that relative addressing 
                // in unmodified instructions are also updated.
                isModelBytesSync = true;
                syncBytes();
            }
        })();
    };

    const syncAssemblyLine = function(lineNumber, text) {
        const range = new monaco.Range(lineNumber, 0, lineNumber, MAX);
        const id = { major: 1, minor: 1 };

        // If the target editor has less lines than the target line to edit,
        // we need to prepend as many newlines as needed to match both editors
        let modelEditor = window.instanceEditor.getModel();
        let linesToAdd = lineNumber - modelEditor.getLineCount();
        while (linesToAdd > 0) {
            text = '\n' + text;
            linesToAdd--;
        }

        isModelEditorSync = true;
        const editOperation = {identifier: id, range: range, text: text, forceMoveMarkers: true};
        window.instanceEditor.executeEdits("custom-code", [ editOperation ]);

        storeAssembly();
    };

    //
    // Language methods
    //

    monaco.languages.register({ id: LANGUAGE_EDITOR });

    monaco.languages.onLanguage(LANGUAGE_EDITOR, async () => {
        monaco.languages.setMonarchTokensProvider(LANGUAGE_EDITOR, {
            tokenizer: {
                root: [
                    [/^\s*\.[0-9a-zA-Z]+:.*/, 'annotation'],
                    [/[a-zA-Z][\w]*/, 'default' ],
                    [/0[xX][0-9a-fA-F]+/, 'number'],
                    [/\d+/, 'number'],
                    [/".*?"/, 'string'],
                ]
            }
        });
    });

    monaco.languages.setLanguageConfiguration(LANGUAGE_EDITOR, {
        // Completions require all tokens to be passed (i.e. mnemonics and operands), so we match printable characters and spaces
        wordPattern: /([^\s]| )+/
    });

    monaco.languages.registerCompletionItemProvider(LANGUAGE_EDITOR, {
        provideCompletionItems: async (model, position) => {
            let editorLineNumber = 0;
            for (let i = 1; i < position.lineNumber + 1; i++) {
                let line = model.getLineContent(i).trimStart();
                if (!line) {
                    continue;
                }
                editorLineNumber++;
            }

            const line = model.getLineContent(position.lineNumber).trimStart();
            if (!line) {
                return { suggestions: [] };
            }

            let baseOffset = parseBaseOffset();
            let [hexLineNumber, hexOffset] = currentByteOffset(editorLineNumber, 1, 0);
            let address = baseOffset + hexOffset;
            let completions = await fetchCompletions([{
                "address": address,
                "data": line
            }]);

            let markers = [];
            let isValidCompletion = false;
            const suggestions = completions[0].reduce((result, k) => {
                if (k.type === "suggestion") {
                    return result.concat({
                        label: line + k.data,
                        kind: monaco.languages.CompletionItemKind.Property,
                        insertText: line + k.data,
                        command: {id: 'editor.action.triggerSuggest', title: 123} // Get next completions for this line with added token
                    });
                } else if (k.type === "bytes") {
                    isValidCompletion = true;
                    let suggestion = {
                        label: `${line} → ${k.data}`,
                        kind: monaco.languages.CompletionItemKind.Property
                    };
                    Object.defineProperty(suggestion, 'insertText', {
                      get: function() {
                          // Since `onDidChangeModelContent()` gets called
                          // before a completion item's command, we instead
                          // set the expected length before bytes get synced,
                          // but after the item was selected, which happens
                          // to be when the text to insert gets read
                          currentSyncBytesLineNumber = position.lineNumber;
                          currentSyncBytesLineLength = k.data.length;
                          currentSyncBytesLineData = k.data;

                          return line;
                      }
                    });
                    return result.concat(suggestion);
                } else if (k.type === "ok") {
                    isValidCompletion = true;
                } else if (k.type === "error") {
                    markers.push({
                        startLineNumber: position.lineNumber,
                        endLineNumber: position.lineNumber,
                        startColumn: 0,
                        endColumn: position.column + 1,
                        message: k.data,
                        severity: monaco.MarkerSeverity.Error,
                    });
                } else if (k.type === "assembly_error") {
                    // x86 spams several constructor errors...
                    // console.error(disassemblyCandidate);
                } else {
                    console.error(`Unknown response at line '${position.lineNumber}': '${JSON.stringify(k)}'`);
                }

                return result;
            }, []);

            // Errors can be returned for ambiguous constructors, but if
            // have a valid pattern we shouldn't show these errors
            if (isValidCompletion) {
                markers = [];
            }
            monaco.editor.setModelMarkers(window.instanceEditor.getModel(), OWNER_EDITOR, markers);

            return { suggestions: suggestions };
        }
    });

    monaco.languages.register({ id: LANGUAGE_BYTES });

    monaco.languages.setLanguageConfiguration(LANGUAGE_BYTES, {
        // Completions require all tokens to be passed (i.e. mnemonics and operands), so we match printable characters and spaces
        wordPattern: /([^\s]| )+/
    });

    monaco.languages.registerCompletionItemProvider(LANGUAGE_BYTES, {
        provideCompletionItems: async (model, position) => {
            let isValidCompletion = false;

            const line = model.getLineContent(position.lineNumber).trimStart();
            if (!line) {
                return { suggestions: [] };
            }

            if (isValidHexString(line)) {
                let disassembledLines = await fetchDisassembly([{
                    "address": 0,
                    "data": line
                }]);
                if (disassembledLines.length > 0 && disassembledLines[0].type === "ok") {
                    syncAssemblyLine(position.lineNumber, disassembledLines[0].data);
                    isValidCompletion = true;
                }
            }

            let markers = [];
            if (!isValidCompletion) {
                markers.push({
                    startLineNumber: position.lineNumber,
                    endLineNumber: position.lineNumber,
                    startColumn: 0,
                    endColumn: position.column + 1,
                    message: 'Invalid hex bytes',
                    severity: monaco.MarkerSeverity.Error,
                });
            }
            monaco.editor.setModelMarkers(window.instanceBytes.getModel(), OWNER_BYTES, markers);

            return { suggestions: [] };
        }
    });

    //
    // State
    //

    // Used to load stored text content when the editor gets initialized,
    // since there's no out-of-the-box functionality for that: https://github.com/microsoft/monaco-editor/issues/115
    var isEditorInitialized = false;

    // Prevent `onDidChangeModelContent()` callbacks from executing when
    // changes were done during syncs, which must be done in a single
    // operation for this to work (either a single call to `setValue()`
    // or `executeEdits()`).
    var isModelBytesSync = false;
    var isModelEditorSync = false;

    var currentSyncBytesLineNumber = INVALID_LINE;
    var currentSyncBytesLineLength = 0;
    var currentSyncBytesLineData = '';

    var cache = [];

    var cacheOffset = 0;
    var cacheOffsetLine = MAX;
    var knownLabels = new Set();

    // Globally visible for tests
    window.instanceEditor = monaco.editor.create(
        document.getElementById('editor'), {
            language: LANGUAGE_EDITOR,
            minimap: {
                enabled: false,
            },
            value: '',
        }
    );
    window.instanceBytes = monaco.editor.create(
        document.getElementById('bytes'), {
            language: LANGUAGE_BYTES,
            minimap: {
                enabled: false,
            },
            value: '',
        }
    );

    //
    // Handlers
    //

    window.instanceEditor.onDidChangeModelContent((context) => {
        const modelEditor = window.instanceEditor.getModel();
        const previousMarkers = monaco.editor.getModelMarkers();
        if (previousMarkers.length > 0
            && previousMarkers[0].owner === OWNER_EDITOR
            && window.instanceEditor.getPosition().lineNumber === previousMarkers[0].startLineNumber) {
            monaco.editor.setModelMarkers(window.instanceEditor.getModel(), OWNER_EDITOR, []);
        }

        if (isModelEditorSync) {
            isModelEditorSync = false;
        } else {
            updateCacheOnChanges(context, modelEditor, KEY_ASM);
            syncBytes();

            storeAssembly();
        }
    });

    window.instanceBytes.onDidChangeModelContent((context) => {
        const modelBytes = window.instanceBytes.getModel();
        const previousMarkers = monaco.editor.getModelMarkers();
        if (previousMarkers.length > 0
            && previousMarkers[0].owner === OWNER_BYTES
            && window.instanceBytes.getPosition().lineNumber === previousMarkers[0].startLineNumber) {
            monaco.editor.setModelMarkers(window.instanceBytes.getModel(), OWNER_BYTES, []);
        }

        if (isModelBytesSync) {
            isModelBytesSync = false;
        } else {
            updateCacheOnChanges(context, modelBytes, KEY_BYTES);
            syncAssemblyEditor();

            storeAssembly();
        }
    });

    (new MutationObserver(function(mutations, observer) {
        mutations.reduce(function(accumulator, current) {
            return accumulator.concat(Array.prototype.slice.call(
                current.addedNodes));
        }, []).forEach((_) => {
            if (!isEditorInitialized) {
                loadAssembly();
                isEditorInitialized = true;
            }
        });
    })).observe(document.querySelector('#editor'), { childList: true });

    document.querySelector('#offset-input').onchange = function() {
        if (isValidHexNumber(document.getElementById('offset-input').value)) {
            syncBytes();
        }
    };

    document.querySelector('#save-bin-button').onclick = function() {
        let data = [];
        const modelBytes = window.instanceBytes.getModel();
        for (let i = 1; i < modelBytes.getLineCount() + 1; i++) {
            const line = modelBytes.getLineContent(i);
            if (!line || (line == UNKNOWN_BYTES)) {
                continue;
            }
            data.push(fromHexStringToU8(line));
        }
        if (data.length === 0) {
            alert("No bytes to save.");
            return;
        }

        const blob = new Blob(data, {type: "application/octet-stream"});
        const fileName = "out.bin";
        saveAs(blob, fileName);
    };

    document.querySelector('#save-patch-button').onclick = function() {
        let data = [];
        const modelBytes = window.instanceBytes.getModel();
        const modelEditor = window.instanceEditor.getModel();
        for (let i = 1; i < modelBytes.getLineCount() + 1; i++) {
            const line = modelBytes.getLineContent(i);
            if (line == UNKNOWN_BYTES) {
                continue;
            }
            const disassembledLine = modelEditor.getLineContent(i).trim();
            if (!disassembledLine) {
                continue;
            } else if (isDirective(disassembledLine)) {
                let candidateOrigin = parseOriginDirective(disassembledLine);
                if (candidateOrigin) {
                    data.push(`\n    f.write(b)\n`);
                    data.push(`\n    f.seek(${candidateOrigin[1]})\n`);
                    data.push(`\n    b = b''\n`);
                }
                continue;
            } else if (disassembledLine.length > 0) {
                data.push(`    # ${disassembledLine}\n`);
            }
            data.push(`    b += b'${fromHexStringToPy(line)}'\n`);
        }
        if (data.length === 0) {
            alert("No bytes to save.");
            return;
        }

        let baseOffset = `0x${(parseBaseOffset()).toString(16)}`;

        let script = `#!/usr/bin/env python3

import sys

with open(sys.argv[1], 'r+b') as f:
    b = b''
${Array.prototype.join.call(data, '')}
    f.write(b)
`

        const blob = new Blob([script], {type: "application/octet-stream"});
        const fileName = "out.py";
        saveAs(blob, fileName);
    };
});
