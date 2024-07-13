require.config({ paths: { vs: '../node_modules/monaco-editor/min/vs' } });

require(['vs/editor/editor.main'], function () {
    //
    // Constants
    //

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
        const modelBytes = instanceBytes.getModel();
        const modelEditor = instanceEditor.getModel();
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
            let newInstanceBytes = [];
            let emptyLines = new Set();
            let requestLines = [];
            const modelBytes = instanceBytes.getModel();
            const modelEditor = instanceEditor.getModel();
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
                    if (i == currentSyncBytesLineNumber) {
                        previousLength = currentSyncBytesLineLength;
                        currentSyncBytesLineNumber = INVALID_LINE;
                        currentSyncBytesLineLength = 0;
                    } else if (cacheAssembly[i] == modelEditor.getLineContent(i)) {
                        if (i >= cacheOffsetLine && (modelBytes.getLineCount() >= i - cacheOffset)) {
                            previousLength = modelBytes.getLineContent(i - cacheOffset).length;
                        } else if (modelBytes.getLineCount() >= i) {
                            previousLength = modelBytes.getLineContent(i).length;
                        }
                    }
                    requestLines.push({
                        "address": baseOffset,
                        "data": line,
                        "previousLength": previousLength
                    });
                }
            }

            let completionSet = await fetchCompletions(requestLines);

            let markers = [];
            let completionIndex = 0;
            for (let i = 1; i < modelEditor.getLineCount() + 1; i++) {
                if (emptyLines.has(i)) {
                    newInstanceBytes.push('');
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
                        }
                    });
                    newInstanceBytes.push(hexBytes);

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

            monaco.editor.setModelMarkers(instanceEditor.getModel(), OWNER_EDITOR, markers);

            isModelBytesSync = true;
            instanceBytes.setValue(newInstanceBytes.join('\n'));

            updateCache();
        })();
    };

    const updateCache = function() {
        const modelBytes = instanceBytes.getModel();
        for (let i = 1; i < modelBytes.getLineCount() + 1; i++) {
            cacheBytes[i] = modelBytes.getLineContent(i);
        }
        const modelEditor = instanceEditor.getModel();
        for (let i = 1; i < modelEditor.getLineCount() + 1; i++) {
            cacheAssembly[i] = modelEditor.getLineContent(i);
        }
    };

    const updateCacheOnBytesChanges = function(context, modelBytes) {
        const modelEditor = instanceEditor.getModel();

        // FIXME: How to handle more than one change?
        const change = context.changes[0];
        const linesBefore = change.range.endLineNumber - change.range.startLineNumber;
        const linesAfter = (change.text.match(/\n/g) || []).length;
        cacheOffset = linesAfter - linesBefore;

        let newCacheBytes = {};
        let newCacheAssembly = {};

        // Before range: Still the same lines.
        for (let i = 1; i < change.range.startLineNumber; i++) {
            if (i in cacheBytes && !!cacheBytes[i]) {
                newCacheBytes[i] = cacheBytes[i];
            } else {
                newCacheBytes[i] = modelBytes.getLineContent(i);
            }
            if (i <= modelEditor.getLineCount()) {
                newCacheAssembly[i] = modelEditor.getLineContent(i);
            }
        }

        // In range: We compare lines, but also account for existing chars in the start and end lines, which are not part of the changed range.
        let newRangeLines = change.text.split('\n');
        newRangeLines[0] = newRangeLines[0] + modelBytes.getLineContent(change.range.startLineNumber).substr(0, change.range.startColumn);
        let newLastIdx = newRangeLines.length - 1;
        if (newLastIdx > 0) {
            newRangeLines[newLastIdx] = newRangeLines[newLastIdx] + modelBytes.getLineContent(change.range.endLineNumber).substr(change.range.endColumn, MAX);
        }
        let rangeIdx = 0;
        let lastInRangeLineNumber = change.range.endLineNumber + cacheOffset + 1;
        cacheOffsetLine = change.range.startLineNumber;
        for (let i = change.range.startLineNumber; i < lastInRangeLineNumber; i++) {
            cacheOffsetLine = i + 1;
            if (i in cacheBytes) {
                candidateBytes = cacheBytes[i];
            }
            if (candidateBytes == newRangeLines[rangeIdx]) {
                newCacheBytes[i] = candidateBytes;
                if (!!candidateBytes) {
                    if (i in cacheAssembly) {
                    newCacheAssembly[i] = cacheAssembly[i];
                    } else {
                        newCacheAssembly[i] = modelEditor.getLineContent(i);
                    }
                }
            } else {
                break;
            }
            rangeIdx += 1;
        }

        // After range: Matching lines are offset, e.g. if new lines were added, then cached lines previously had smaller line numbers, or vice-versa.
        for (let i = cacheOffsetLine; i < modelBytes.getLineCount() + 1; i++) {
            if ((i - cacheOffset) in cacheBytes) {
                newCacheBytes[i] = cacheBytes[i - cacheOffset];
            }

            if ((i - cacheOffset) > 0 && (i - cacheOffset) <= modelEditor.getLineCount()) {
                newCacheAssembly[i] = modelEditor.getLineContent(i - cacheOffset);
            }
        }

        //console.log(cacheOffset, cacheOffsetLine, "byt", cacheBytes, newCacheBytes, "asm", cacheAssembly, newCacheAssembly);
        cacheBytes = newCacheBytes;
        cacheAssembly = newCacheAssembly;
    };

    const updateCacheOnAssemblyChanges = function(context, model) {
        const modelBytes = instanceBytes.getModel();

        // FIXME: How to handle more than one change?
        const change = context.changes[0];
        const linesBefore = change.range.endLineNumber - change.range.startLineNumber;
        const linesAfter = (change.text.match(/\n/g) || []).length;
        cacheOffset = linesAfter - linesBefore;
        cacheOffsetLine = MAX;

        let newCacheAssembly = {};

        // Before range: Still the same lines.
        for (let i = 1; i < change.range.startLineNumber; i++) {
            if (i in cacheAssembly) {
                newCacheAssembly[i] = cacheAssembly[i];
            }
        }

        // In range: We compare lines, but also account for existing chars in the start and end lines, which are not part of the changed range.
        let newRangeLines = change.text.split('\n');
        newRangeLines[0] = newRangeLines[0] + model.getLineContent(change.range.startLineNumber).substr(0, change.range.startColumn);
        let newLastIdx = newRangeLines.length - 1;
        if (newLastIdx > 0) {
            newRangeLines[newLastIdx] = newRangeLines[newLastIdx] + model.getLineContent(change.range.endLineNumber).substr(change.range.endColumn, MAX);
        }
        let rangeIdx = 0;
        for (let i = change.range.startLineNumber; i < change.range.endLineNumber + 1; i++) {
            if (cacheAssembly[i] == newRangeLines[rangeIdx]) {
                newCacheAssembly[i] = cacheAssembly[i];
                // If we don't see any mismatch in range, then this will
                // be the next line after the range.
                cacheOffsetLine = i + 1;
            } else {
                cacheOffsetLine = i;
                break;
            }
            rangeIdx += 1;
        }

        // After range: Matching lines are offset, e.g. if new lines were added, then cached lines previously had smaller line numbers, or vice-versa.
        for (let i = cacheOffsetLine; i < model.getLineCount() + 1; i++) {
            if ((i - cacheOffset) in cacheAssembly) {
                newCacheAssembly[i] = cacheAssembly[i - cacheOffset];
            }
        }

        // Nothing matched, might be a paste on an empty editor?
        if (Object.keys(newCacheAssembly).length == 0) {
            cacheOffset = 0;
            cacheOffsetLine = MAX;
        } else {
            //console.log(cacheOffset, cacheOffsetLine, cacheAssembly, newCacheAssembly);
            cacheAssembly = newCacheAssembly;
        }
    };

    const syncBytesLine = function(lineNumber, text) {
        const range = new monaco.Range(lineNumber, 0, lineNumber, MAX);
        const id = { major: 1, minor: 1 };

        // If the target editor has less lines than the target line to edit,
        // we need to prepend as many newlines as needed to match both editors
        const modelBytes = instanceBytes.getModel();
        let linesToAdd = lineNumber - modelBytes.getLineCount();
        while (linesToAdd > 0) {
            text = '\n' + text;
            linesToAdd--;
        }

        isModelBytesSync = true;
        const editOperation = {identifier: id, range: range, text: text, forceMoveMarkers: true};
        instanceBytes.executeEdits("custom-code", [ editOperation ]);
    };

    const syncAssemblyEditor = function() {
        (async () => {
            let baseOffset = parseBaseOffset();
            let cacheAssemblyEditor = [];
            let emptyLines = new Set();
            let requestLines = [];
            const modelBytes = instanceBytes.getModel();
            const modelEditor = instanceEditor.getModel();
            for (let i = 1; i < modelBytes.getLineCount() + 1; i++) {
                let line = modelBytes.getLineContent(i).trim();
                if (!line) {
                    emptyLines.add(i);
                } else {
                    requestLines.push({
                        "address": baseOffset,
                        "data": line
                    });
                }
            }

            let disassemblySet = await fetchDisassembly(requestLines);

            let markers = [];
            let disassemblyIndex = 0;
            for (let i = 1; i < modelBytes.getLineCount() + 1; i++) {
                if (emptyLines.has(i)) {
                    if (i in cacheAssembly) {
                        // Preserve directives
                        cacheAssemblyEditor.push(cacheAssembly[i]);
                    } else {
                        // Empty on both editors
                        cacheAssemblyEditor.push('');
                    }
                } else if (i in cacheAssembly 
                        && cacheAssembly[i].split(/[^\w]/)[0] == disassemblySet[disassemblyIndex].split(/[^\w]/)[0]
                        && hasLabel(cacheAssembly[i]) 
                        && !hasLabel(disassemblySet[disassemblyIndex])) {
                    // Preserve instructions with user-defined labels
                    // if the mnemonic is the same after edits
                    cacheAssemblyEditor.push(cacheAssembly[i]);
                } else if (disassemblyIndex < disassemblySet.length) {
                    let disassembly = disassemblySet[disassemblyIndex];
                    cacheAssemblyEditor.push(disassembly);

                    disassemblyIndex++;
                } else {
                    markers.push({
                        startLineNumber: i,
                        endLineNumber: i,
                        startColumn: 0,
                        endColumn: MAX,
                        message: `Line not in disassembly set (${disassemblyIndex} >= ${disassemblySet.length})`,
                        severity: monaco.MarkerSeverity.Error,
                    });
                }
            }

            monaco.editor.setModelMarkers(instanceEditor.getModel(), OWNER_EDITOR, markers);

            isModelEditorSync = true;
            instanceEditor.setValue(cacheAssemblyEditor.join('\n'));
        })();
    };

    const syncAssemblyLine = function(lineNumber, text) {
        const range = new monaco.Range(lineNumber, 0, lineNumber, MAX);
        const id = { major: 1, minor: 1 };

        // If the target editor has less lines than the target line to edit,
        // we need to prepend as many newlines as needed to match both editors
        let modelEditor = instanceEditor.getModel();
        let linesToAdd = lineNumber - modelEditor.getLineCount();
        while (linesToAdd > 0) {
            text = '\n' + text;
            linesToAdd--;
        }

        isModelEditorSync = true;
        const editOperation = {identifier: id, range: range, text: text, forceMoveMarkers: true};
        instanceEditor.executeEdits("custom-code", [ editOperation ]);
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
                }

                return result;
            }, []);

            // Errors can be returned for ambiguous constructors, but if
            // have a valid pattern we shouldn't show these errors
            if (isValidCompletion) {
                markers = [];
            }
            monaco.editor.setModelMarkers(instanceEditor.getModel(), OWNER_EDITOR, markers);

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
                if (disassembledLines.length > 0) {
                    syncAssemblyLine(position.lineNumber, disassembledLines[0]);
                    isValidCompletion = true;
                }
            }

            markers = [];
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
            monaco.editor.setModelMarkers(instanceBytes.getModel(), OWNER_BYTES, markers);

            return { suggestions: [] };
        }
    });

    //
    // State
    //

    // Prevent `onDidChangeModelContent()` callbacks from executing when
    // changes were done during syncs, which must be done in a single
    // operation for this to work (either a single call to `setValue()`
    // or `executeEdits()`).
    var isModelBytesSync = false;
    var isModelEditorSync = false;

    var currentSyncBytesLineNumber = INVALID_LINE;
    var currentSyncBytesLineLength = 0;

    var cacheAssembly = {};
    var cacheBytes = {};
    var cacheOffset = 0;
    var cacheOffsetLine = MAX;
    var knownLabels = new Set();

    var instanceEditor = monaco.editor.create(
        document.getElementById('editor'), {
            language: LANGUAGE_EDITOR,
            minimap: {
                enabled: false,
            },
            value: '',
        }
    );
    var instanceBytes = monaco.editor.create(
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

    const commandSyncBytesId = instanceEditor.addCommand(
        0,
        function (_, ...args) {
            const lineNumber = args[0].lineNumber;
            const line = args[1];
            const hexBytes = args[2];
            //console.log(_, args);

            syncBytesLine(lineNumber, hexBytes);
        },
        ""
    );

    instanceEditor.onDidChangeModelContent((context) => {
        const modelEditor = instanceEditor.getModel();
        const previousMarkers = monaco.editor.getModelMarkers();
        if (previousMarkers.length > 0
            && previousMarkers[0].owner === OWNER_EDITOR
            && instanceEditor.getPosition().lineNumber === previousMarkers[0].startLineNumber) {
            monaco.editor.setModelMarkers(instanceEditor.getModel(), OWNER_EDITOR, []);
        }

        if (isModelEditorSync) {
            isModelEditorSync = false;
        } else {
            updateCacheOnAssemblyChanges(context, modelEditor);
            syncBytes();
        }
    });

    instanceBytes.onDidChangeModelContent((context) => {
        const modelBytes = instanceBytes.getModel();
        const previousMarkers = monaco.editor.getModelMarkers();
        if (previousMarkers.length > 0
            && previousMarkers[0].owner === OWNER_BYTES
            && instanceBytes.getPosition().lineNumber === previousMarkers[0].startLineNumber) {
            monaco.editor.setModelMarkers(instanceBytes.getModel(), OWNER_BYTES, []);
        }

        if (isModelBytesSync) {
            isModelBytesSync = false;
        } else {
            updateCacheOnBytesChanges(context, modelBytes);
            syncAssemblyEditor();
        }
    });

    document.querySelector('#offset-input').onchange = function() {
        if (isValidHexNumber(document.getElementById('offset-input').value)) {
            syncBytes();
        }
    };

    document.querySelector('#save-bin-button').onclick = function() {
        let data = [];
        const modelBytes = instanceBytes.getModel();
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
        const modelBytes = instanceBytes.getModel();
        const modelEditor = instanceEditor.getModel();
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
