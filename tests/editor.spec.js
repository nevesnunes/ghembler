// @ts-check
const { test, expect } = require('@playwright/test');

// Note: Inner text from locators for editor lines do not return a
// consistent order, we need to use generic assertions over model contents
// with retries, to also account for contents being empty before
// being updated with expected values.
test.describe('Tests', () => {
	let globalPage;
    // Retry intervals are not respected in toPass(), only taking a few ms between attempts.
    // As a workaround, explicit delays are used on getAssemblyText() / getBytesText().
    const globalRetry = { timeout: 2000 };

    async function triggerAssemblyEditorCommand(commandId, args) {
        return await globalPage.evaluate(
			`window.instanceAssembly.trigger(null, '${commandId}', ${args ? JSON.stringify(args) : 'undefined'});`
        );
    }

    async function triggerBytesEditorCommand(commandId, args) {
        return await globalPage.evaluate(
			`window.instanceBytes.trigger(null, '${commandId}', ${args ? JSON.stringify(args) : 'undefined'});`
        );
    }

    async function editAssemblyEditor(range, text) {
        return await globalPage.evaluate(`
            const range = new monaco.Range(${range});
            const id = { major: 1, minor: 1 };
            const editOperation = {identifier: id, range: range, text: '${text}', forceMoveMarkers: true};
            window.instanceAssembly.executeEdits("custom-code", [ editOperation ]);
        `);
    }

    async function editBytesEditor(range, text) {
        return await globalPage.evaluate(`
            const range = new monaco.Range(${range});
            const id = { major: 1, minor: 1 };
            const editOperation = {identifier: id, range: range, text: '${text}', forceMoveMarkers: true};
            window.instanceBytes.executeEdits("custom-code", [ editOperation ]);
        `);
    }

    async function getAssemblyText() {
        return await globalPage.evaluate(async () => {
            const delay = ms => new Promise(res => setTimeout(res, ms));
            await delay(100);
            return window.instanceAssembly.getModel().getLinesContent().join('\n');
        });
    }

    async function getBytesText() {
        return await globalPage.evaluate(async () => {
            const delay = ms => new Promise(res => setTimeout(res, ms));
            await delay(100);
            return window.instanceBytes.getModel().getLinesContent().join('\n');
        });
    }

    test.beforeEach(async ({ page }) => {
        globalPage = page;
        await page.goto('http://localhost:8000/');
    });

    test('on assembly typed', async ({ page }) => {

        const assemblyText = `
MOV AX,123
.lbl:foo
NOP
.org:0xa
JMP foo
`
        const bytesText = `
66 b8 7b 00

90

eb f8
`

        await triggerAssemblyEditorCommand('type', { text: assemblyText });

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly fetched').toEqual(assemblyText);
            expect(await getBytesText(), 'bytes fetched').toEqual(bytesText);
        }).toPass(globalRetry);

        // Insert newline at line start
        await editAssemblyEditor('5, 1, 5, 1', '\\n');

        const assemblyTextAfterInsert = `
MOV AX,123
.lbl:foo
NOP

.org:0xa
JMP foo
`
        const bytesTextAfterInsert = `
66 b8 7b 00

90


eb f8
`

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on insert at start of line 5')
                .toEqual(assemblyTextAfterInsert);
            expect(await getBytesText(), 'bytes on insert at end start line 5')
                .toEqual(bytesTextAfterInsert);
        }).toPass(globalRetry);

        // Delete newline
        await editAssemblyEditor('5, 1, 6, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete at line 5')
                .toEqual(assemblyText);
            expect(await getBytesText(), 'bytes on delete at line 5')
                .toEqual(bytesText);
        }).toPass(globalRetry);

        const assemblyTextAfterInsertAtEnd = `
MOV AX,123
.lbl:foo
NOP
.org:0xa

JMP foo
`

        // Insert newline at line end
        await editAssemblyEditor('5, 9, 5, 9', '\\n');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on insert #2 at end of line 5')
                .toEqual(assemblyTextAfterInsertAtEnd);
            expect(await getBytesText(), 'bytes on insert #2 at end of line 5')
                .toEqual(bytesTextAfterInsert);
        }).toPass(globalRetry);

        const assemblyTextAfterDeleteAtEnd = `
MOV AX,123
.lbl:foo
NOP

JMP foo
`
        // Origin directive no longer applied, relative jump has smaller displacement
        const bytesTextAfterDeleteAtEnd = `
66 b8 7b 00

90

eb fd
`

        // Delete newline
        await editAssemblyEditor('5, 1, 6, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete #2 at line 5')
                .toEqual(assemblyTextAfterDeleteAtEnd);
            expect(await getBytesText(), 'bytes on delete #2 at line 5')
                .toEqual(bytesTextAfterDeleteAtEnd);
        }).toPass(globalRetry);
    });

    test('on assembly multiline typed', async ({ page }) => {
        const assemblyText = `
MOV AX,123
.lbl:foo
NOP
.org:0xa
JMP foo
`
        const bytesText = `
66 b8 7b 00

90

eb f8
`

        await triggerAssemblyEditorCommand('type', { text: assemblyText });

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly fetched').toEqual(assemblyText);
            expect(await getBytesText(), 'bytes fetched').toEqual(bytesText);
        }).toPass(globalRetry);

        const assemblyTextAfterMultilineInsert = `
MOV AX,123



.lbl:foo
NOP
.org:0xa
JMP foo
`
        const bytesTextAfterMultilineInsert = `
66 b8 7b 00




90

eb f8
`

        // Insert 3 newlines
        await editAssemblyEditor('3, 1, 3, 1', '\\n\\n\\n');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on insert at start of line 2')
                .toEqual(assemblyTextAfterMultilineInsert);
            expect(await getBytesText(), 'bytes on insert at start of line 2')
                .toEqual(bytesTextAfterMultilineInsert);
        }).toPass(globalRetry);

        const assemblyTextAfterSecondDirectiveInsert = `
MOV AX,123



.lbl:foo
NOP


.org:0xa
JMP foo
`
        const bytesTextAfterSecondDirectiveInsert = `
66 b8 7b 00




90



eb f8
`
        // Insert 2 newlines
        await editAssemblyEditor('8, 1, 8, 1', '\\n\\n');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on insert #2')
                .toEqual(assemblyTextAfterSecondDirectiveInsert);
            expect(await getBytesText(), 'bytes on insert #2')
                .toEqual(bytesTextAfterSecondDirectiveInsert);
        }).toPass(globalRetry);

        const assemblyTextAfterFirstDirectiveDelete = `
MOV AX,123


.lbl:foo
NOP


.org:0xa
JMP foo
`
        const bytesTextAfterFirstDirectiveDelete = `
66 b8 7b 00



90



eb f8
`
        // Delete newline
        await editAssemblyEditor('3, 1, 4, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete at line 2')
                .toEqual(assemblyTextAfterFirstDirectiveDelete);
            expect(await getBytesText(), 'bytes on delete at line 2')
                .toEqual(bytesTextAfterFirstDirectiveDelete);
        }).toPass(globalRetry);
    });

    test('on bytes typed', async ({ page }) => {
        let assemblyText = `
MOV AX,0x7b

NOP

JMP 0x00000008
`
        let bytesText = `
66 c7 c0 7b 00

f2 48 90

4f e9 fa ff ff ff
`

        await triggerBytesEditorCommand('type', { text: bytesText });

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly fetched').toEqual(assemblyText);
            expect(await getBytesText(), 'bytes fetched').toEqual(bytesText);
        }).toPass(globalRetry);

        // Insert newline
        await editBytesEditor('5, 1, 5, 1', '\\n');

        const assemblyTextAfterInsert = `
MOV AX,0x7b

NOP


JMP 0x00000008
`
        const bytesTextAfterInsert = `
66 c7 c0 7b 00

f2 48 90


4f e9 fa ff ff ff
`

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on insert at start of line 5')
                .toEqual(assemblyTextAfterInsert);
            expect(await getBytesText(), 'bytes on insert at start of line 5')
                .toEqual(bytesTextAfterInsert);
        }).toPass(globalRetry);

        // Delete newline
        await editBytesEditor('5, 1, 6, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete at start of line 5')
                .toEqual(assemblyText);
            expect(await getBytesText(), 'bytes on delete at start of line 5')
                .toEqual(bytesText);
        }).toPass(globalRetry);

        // Insert newline
        await editBytesEditor('5, 9, 5, 9', '\\n');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on insert #2 at end of line 5')
                .toEqual(assemblyTextAfterInsert);
            expect(await getBytesText(), 'bytes on insert #2 at end of line 5')
                .toEqual(bytesTextAfterInsert);
        }).toPass(globalRetry);

        // Delete newline
        await editBytesEditor('5, 1, 6, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete #2 at end of line 5')
                .toEqual(assemblyText);
            expect(await getBytesText(), 'bytes on delete #2 at end of line 5')
                .toEqual(bytesText);
        }).toPass(globalRetry);
    });

    test('on bytes multiline typed', async ({ page }) => {
        let assemblyText = `
MOV AX,0x7b

NOP
JMP 0x00000008
`
        let bytesText = `
66 c7 c0 7b 00

f2 48 90
4f e9 fa ff ff ff
`

        await triggerBytesEditorCommand('type', { text: bytesText });

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly fetched').toEqual(assemblyText);
            expect(await getBytesText(), 'bytes fetched').toEqual(bytesText);
        }).toPass(globalRetry);

        // Insert 3 newlines
        await editBytesEditor('4, 9, 4, 9', '\\nC3\\n\\n');

        const assemblyTextAfterInsert = `
MOV AX,0x7b

NOP
RET


JMP 0x00000009
`
        const bytesTextAfterInsert = `
66 c7 c0 7b 00

f2 48 90
c3


4f e9 fa ff ff ff
`

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on insert at start of line 5')
                .toEqual(assemblyTextAfterInsert);
            expect(await getBytesText(), 'bytes on insert at start of line 5')
                .toEqual(bytesTextAfterInsert);
        }).toPass(globalRetry);

        // Delete 3 newlines
        await editBytesEditor('5, 1, 8, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete at start of line 5')
                .toEqual(assemblyText);
            expect(await getBytesText(), 'bytes on delete at start of line 5')
                .toEqual(bytesText);
        }).toPass(globalRetry);
    });
});
