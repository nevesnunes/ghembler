// @ts-check
const { test, expect } = require('@playwright/test');

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

        expect(await page.locator(`#bytes .view-lines`), 'bytes fetched')
            .toHaveText(bytesText, { useInnerText: true });

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

        expect(await page.locator(`#editor .view-lines`), 'assembly on insert at line 5')
            .toHaveText(assemblyTextAfterInsert, { useInnerText: true });
        expect(await page.locator(`#bytes .view-lines`), 'bytes on insert at line 5')
            .toHaveText(bytesTextAfterInsert, { useInnerText: true });

        // Delete newline
        await editAssemblyEditor('5, 1, 6, 1', '');

        expect(await page.locator(`#editor .view-lines`), 'assembly on delete at line 5')
            .toHaveText(assemblyText, { useInnerText: true });
        expect(await page.locator(`#bytes .view-lines`), 'bytes on delete at line 5')
            .toHaveText(bytesText, { useInnerText: true });
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

        expect(await page.locator(`#editor .view-lines`), 'assembly fetched').toHaveText(assemblyText, { useInnerText: true });

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

        expect(await page.locator(`#editor .view-lines`), 'assembly on insert at line 5')
            .toHaveText(assemblyTextAfterInsert, { useInnerText: true });
        expect(await page.locator(`#bytes .view-lines`), 'bytes on insert at line 5')
            .toHaveText(bytesTextAfterInsert, { useInnerText: true });

        // Delete newline
        await editBytesEditor('5, 1, 6, 1', '');

        expect(await page.locator(`#editor .view-lines`), 'assembly on delete at line 5')
            .toHaveText(assemblyText, { useInnerText: true });
        expect(await page.locator(`#bytes .view-lines`), 'bytes on delete at line 5')
            .toHaveText(bytesText, { useInnerText: true });
    });
});
