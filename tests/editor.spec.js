// @ts-check
const { test, expect } = require('@playwright/test');

// Note: Inner text from locators for editor lines do not return a
// consistent order, we need to use generic assertions over model contents 
// with retries, to also account for contents being empty before 
// being updated with expected values.
test.describe('Tests', () => {
	let globalPage;

    async function triggerAssemblyEditorCommand(commandId, args) {
        return await globalPage.evaluate(
			`window.instanceEditor.trigger(null, '${commandId}', ${args ? JSON.stringify(args) : 'undefined'});`
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
            window.instanceEditor.executeEdits("custom-code", [ editOperation ]);
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
        return await globalPage.evaluate(() => window.instanceEditor.getModel().getLinesContent().join('\n'));
    }

    async function getBytesText() {
        return await globalPage.evaluate(() => window.instanceBytes.getModel().getLinesContent().join('\n'));
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
            expect(await getBytesText(), 'bytes fetched').toEqual(bytesText);
        }).toPass({ timeout: 2000 });

        // Insert newline
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
            expect(await getAssemblyText(), 'assembly on insert at line 5').toEqual(assemblyTextAfterInsert);
            expect(await getBytesText(), 'bytes on insert at line 5').toEqual(bytesTextAfterInsert);
        }).toPass({ timeout: 2000 });

        // Delete newline
        await editAssemblyEditor('5, 1, 6, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete at line 5').toEqual(assemblyText);
            expect(await getBytesText(), 'bytes on delete at line 5').toEqual(bytesText);
        }).toPass({ timeout: 2000 });
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
        }).toPass({ timeout: 2000 });

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
            expect(await getAssemblyText(), 'assembly on insert at line 5').toEqual(assemblyTextAfterInsert);
            expect(await getBytesText(), 'bytes on insert at line 5').toEqual(bytesTextAfterInsert);
        }).toPass({ timeout: 2000 });

        // Delete newline
        await editBytesEditor('5, 1, 6, 1', '');

        await expect(async () => {
            expect(await getAssemblyText(), 'assembly on delete at line 5').toEqual(assemblyText);
            expect(await getBytesText(), 'bytes on delete at line 5').toEqual(bytesText);
        }).toPass({ timeout: 2000 });
    });
});
