require.config({ paths: { vs: '../node_modules/monaco-editor/min/vs' } });

require(['vs/editor/editor.main'], function () {
    // Constants

    const LANGUAGE_EDITOR = 'langEditor';
    const LANGUAGE_BYTES = 'langBytes';
    const OWNER_EDITOR = 'ownerEditor';
    const OWNER_BYTES = 'ownerBytes';
    const UNKNOWN_BYTES = '??';

    // Helper methods

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
        let model = instanceBytes.getModel();
        for (var i = startLineNumber; i < model.getLineCount() + 1; i++) {
            if (i === editorLineNumber) {
                break;
            }
            let line = model.getLineContent(i).trimStart();
            if (!line) {
                continue;
            }
            if (isValidHexString(line)) {
                line.replace(/\s/g, '').match(/.{1,2}/g).map((_) => { offset++; });
            } else {
                console.error(`Invalid hex string @ ${line}`);
            }
        }
        return [i, offset];
    };

    const syncBytes = function() {
        (async () => {
            let baseOffset = parseBaseOffset();
            let cacheBytes = [];
            let emptyLines = new Set();
            let requestLineNumber = 1;
            let requestLines = [];
            const modelBytes = instanceBytes.getModel();
            const modelEditor = instanceEditor.getModel();
            for (let i = 1; i < modelEditor.getLineCount() + 1; i++) {
                let line = modelEditor.getLineContent(i).trimStart();
                if (!line) {
                    emptyLines.add(i);
                    continue;
                }

                let previousLength = 0;
                if (modelBytes.getLineCount() >= i) {
                    previousLength = modelBytes.getLineContent(i).length;
                }
                requestLines.push({
                    "address": baseOffset,
                    "data": line,
                    "previousLength": previousLength
                });

                requestLineNumber++;
            }

            let completionSet = await fetchCompletions(requestLines);

            let completionIndex = 0;
            for (let i = 1; i < modelEditor.getLineCount() + 1; i++) {
                if (emptyLines.has(i)) {
                    cacheBytes.push('');
                } else if (completionIndex < completionSet.length) {
                    let completions = completionSet[completionIndex];
                    let hexBytes = UNKNOWN_BYTES;
                    completions.forEach((completion) => {
                        if (completion.type === "bytes") {
                            hexBytes = completion.data;
                        } else if (completion.type === "error") {
                            // x86 spams several constructor errors...
                            // console.error(completion.data);
                        }
                    });
                    cacheBytes.push(hexBytes);

                    completionIndex++;
                } else {
                    console.error(`OOB completionIndex ${completionIndex}`);
                }
            }

            instanceBytes.setValue(cacheBytes.join('\n'));
        })();
    };

    const syncBytesLine = function(lineNumber, text) {
        const range = new monaco.Range(lineNumber, 0, lineNumber, 9999);
        const id = { major: 1, minor: 1 };

        // If the target editor has less lines than the target line to edit,
        // we need to prepend as many newlines as needed to match both editors
        let modelBytes = instanceBytes.getModel();
        let linesToAdd = lineNumber - modelBytes.getLineCount();
        while (linesToAdd > 0) {
            text = '\n' + text;
            linesToAdd--;
        }

        const editOperation = {identifier: id, range: range, text: text, forceMoveMarkers: true};
        instanceBytes.executeEdits("custom-code", [ editOperation ]);
    };

    const syncDisassemblyLine = function(lineNumber, text) {
        const range = new monaco.Range(lineNumber, 0, lineNumber, 9999);
        const id = { major: 1, minor: 1 };

        // If the target editor has less lines than the target line to edit,
        // we need to prepend as many newlines as needed to match both editors
        let modelEditor = instanceEditor.getModel();
        let linesToAdd = lineNumber - modelEditor.getLineCount();
        while (linesToAdd > 0) {
            text = '\n' + text;
            linesToAdd--;
        }

        const editOperation = {identifier: id, range: range, text: text, forceMoveMarkers: true};
        instanceEditor.executeEdits("custom-code", [ editOperation ]);
    };

    // Language methods

    monaco.languages.register({ id: LANGUAGE_EDITOR });

    monaco.languages.onLanguage(LANGUAGE_EDITOR, async () => {
        monaco.languages.setMonarchTokensProvider(LANGUAGE_EDITOR, {
            tokenizer: {
                root: [
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
                        kind: "monaco.languages.CompletionItemKind.Keyword",
                        insertText: line + k.data,
                        command: {id: 'editor.action.triggerSuggest', title: 123} // Get next completions for this line with added token
                    });
                } else if (k.type === "bytes") {
                    isValidCompletion = true;
                    return result.concat({
                        label: `${line} => ${k.data}`,
                        kind: "monaco.languages.CompletionItemKind.Keyword",
                        insertText: line,
                        command: {
                            id: commandSyncBytesId,
                            title: "Sync bytes",
                            arguments: [position, line, k.data]
                        }
                    })
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
                    syncDisassemblyLine(position.lineNumber, disassembledLines[0]);
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

    // State

    var isPasted = false;
    var previousInstructionLineCount = 0;

    var instanceEditor = monaco.editor.create(
        document.getElementById('editor'), {
            value: '',
            language: LANGUAGE_EDITOR,
            minimap: {
                enabled: false,
            },
        }
    );
    var instanceBytes = monaco.editor.create(
        document.getElementById('bytes'), {
            value: '',
            language: LANGUAGE_BYTES,
            minimap: {
                enabled: false,
            },
        }
    );

    // Handlers

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

    instanceEditor.onDidChangeModelContent((_) => {
        const model = instanceEditor.getModel();
        const previousMarkers = monaco.editor.getModelMarkers();
        if (previousMarkers.length > 0
            && previousMarkers[0].owner === OWNER_EDITOR
            && instanceEditor.getPosition().lineNumber === previousMarkers[0].startLineNumber) {
            monaco.editor.setModelMarkers(instanceEditor.getModel(), OWNER_EDITOR, []);
        }

        if (!isPasted && (previousInstructionLineCount != model.getLineCount())) {
            previousInstructionLineCount = model.getLineCount();
            syncBytes();
        }
    });

    instanceEditor.onDidPaste((_) => {
        try {
            isPasted = true;
            syncBytes();
        } finally {
            isPasted = false;
        }
    });

    document.querySelector('#offset-input').onchange = function() {
        if (isValidHexNumber(document.getElementById('offset-input').value)) {
            syncBytes();
        }
    };

    document.querySelector('#save-bin-button').onclick = function() {
        let data = [];
        const model = instanceBytes.getModel();
        for (let i = 1; i < model.getLineCount() + 1; i++) {
            const line = model.getLineContent(i);
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
            if (!line || (line == UNKNOWN_BYTES)) {
                continue;
            }
            const disassembledLine = modelEditor.getLineContent(i).trim();
            if (disassembledLine.length > 0) {
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

with open(sys.argv[1], 'wb') as f:
    f.seek(${baseOffset})

    b = b''
${Array.prototype.join.call(data, '')}
    f.write(b)
`

        const blob = new Blob([script], {type: "application/octet-stream"});
        const fileName = "out.py";
        saveAs(blob, fileName);
    };
});
