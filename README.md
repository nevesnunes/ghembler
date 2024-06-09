# SLEIGHed

Assembler and Disassembler for Ghidra processor modules featuring auto-completion. (WIP)

Example using [Toshiba TLCS-900/H](https://github.com/nevesnunes/ghidra-tlcs900h):

![](./example.png)

## Running

Backend (Ghidra script):

```sh
# Create zero-filled file so that the script has a program available
dd if=/dev/zero of=/tmp/0.bin bs=1024 iflag=count_bytes count=$((0x10000))

# Run script headless, wait until ready:
# INFO  AsmServer.java> Listening at port 18000... (GhidraScript)
GHIDRA_INSTALL_DIR=FIXME
GHIDRA_PROJECT_DIR=FIXME
GHIDRA_PROJECT_NAME=FIXME
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$GHIDRA_PROJECT_DIR/" "$GHIDRA_PROJECT_NAME/_headless" \
        -import /tmp/0.bin \
        -overwrite \
        -processor 'TLCS900H:LE:32:default' \
        -noanalysis \
        -scriptPath ./ghidra_scripts \
        -postScript AsmServer.java
```

Frontend:

```sh
npm install
npm run server
```

[Optional] Sanity check:

```sh
# Expecting two encodings returned when assembling the given instruction
curl -X POST -H "Content-Type: text/plain" --data "jp NZ/NE,XWA+1" http://localhost:18000/assemble | jq .
# [
#   {
#     "type": "bytes",
#     "data": "b8 01 de"
#   },
#   {
#     "type": "bytes",
#     "data": "f3 e1 01 00 de"
#   }
# ]
```

## Related work

- [GitHub \- ret2jazzy/disasm\.pro: A realtime assembler/disassembler \(formerly known as disasm\.ninja\)](https://github.com/ret2jazzy/disasm.pro)
