require.config({ paths: { vs: '../node_modules/monaco-editor/min/vs' } });

require(['vs/editor/editor.main'], function () {
    // Constants

    const LANGUAGE_EDITOR = 'langEditor';
    const LANGUAGE_BYTES = 'langBytes';
    const OWNER_EDITOR = 'ownerEditor';
    const OWNER_BYTES = 'ownerBytes';
    const UNKNOWN_BYTES = '??';

    // Helper methods

    const toCacheKey = (lineNumber, line) => { return `${lineNumber}:${line}`; };

    const isValidHexString = (hexString) => {
        const trimmedHexString = hexString.replace(/\s/g, '');
        return trimmedHexString.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(trimmedHexString);
    };

    const fromHexString = (hexString) =>
        Uint8Array.from(hexString.replace(/\s/g, '').match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

    const fetchCompletions = async (line) => {
        let completions = [];
        const requestConfig = {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'text/plain',
            },
            body: line
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

    const syncBytes = function() {
        (async () => {
            let instanceBytesValues = [];
            let model = instanceEditor.getModel();
            for (let i = 1; i < model.getLineCount() + 1; i++) {
                let line = model.getLineContent(i);
                if (!line) {
                    continue;
                }
                let hexBytes = disasmCache[toCacheKey(i, line)];
                if (!hexBytes) {
                    hexBytes = UNKNOWN_BYTES;

                    let completions = await fetchCompletions(line);
                    completions.forEach((completion) => {
                        if (completion.type === "bytes") {
                            hexBytes = completion.data;
                            disasmCache[toCacheKey(i, line)] = hexBytes;
                        }
                    });
                }
                instanceBytesValues.push(hexBytes);
            }

            instanceBytes.setValue(instanceBytesValues.join('\n'));
        })();
    };

    const syncDisassemblyLine = function(lineNumber, text) {
        const range = new monaco.Range(lineNumber, 0, lineNumber, 9999);
        const id = { major: 1, minor: 1 };

        // If the target editor has less lines than the target line to edit,
        // we need to prepend as many newlines as needed to match both editors
        let model = instanceEditor.getModel();
        let linesToAdd = lineNumber - model.getLineCount();
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
            const line = model.getLineContent(position.lineNumber).trimStart();
            if (!line) {
                return { suggestions: [] };
            }

            let completions = await fetchCompletions(line);

            let markers = [];
            let isValidCompletion = false;
            const suggestions = completions.reduce((result, k) => {
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

    var previousInstructionLineCount = 0;
    var disasmCache = {};
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
            console.log(_, args);

            disasmCache[toCacheKey(lineNumber, line)] = hexBytes;

            syncBytes();
        },
        ""
    );

    instanceEditor.onDidChangeModelContent((_) => {
        let model = instanceEditor.getModel();
        let previousMarkers = monaco.editor.getModelMarkers();
        if (previousMarkers.length > 0
            && previousMarkers[0].owner === OWNER_EDITOR
            && instanceEditor.getPosition().lineNumber === previousMarkers[0].startLineNumber) {
            monaco.editor.setModelMarkers(instanceEditor.getModel(), OWNER_EDITOR, []);
        }
        if (previousInstructionLineCount != model.getLineCount()) {
            previousInstructionLineCount = model.getLineCount();
            syncBytes();
        }
    });

    instanceEditor.onDidPaste((_) => {
        syncBytes();
    });

    document.querySelector('#save-button').onclick = function() {
        let data = [];
        let model = instanceBytes.getModel();
        for (let i = 1; i < model.getLineCount() + 1; i++) {
            let line = model.getLineContent(i);
            if (!line || (line == UNKNOWN_BYTES)) {
                continue;
            }
            data.push(fromHexString(line));
        }
        if (data.length === 0) {
            alert("No bytes to save.");
            return;
        }

        let blob = new Blob(data, {type: "application/octet-stream"});
        let fileName = "out.bin";
        saveAs(blob, fileName);
    };
});
