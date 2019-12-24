# FFXIV Opcodes
A shared effort to maintain FFXIV opcode mappings

# Automated Opcode Correction

This repo contains some (wip) tooling to automate the opcode updating process. How it works and more detailed instructions can be found on the [blog post](https://sapphireserver.github.io/dev/2019/12/23/fixing-opcodes.html).

Relevant files:
* `xiv-opcode-parser.py` - IDA script to output a schema generated from the client exe
* `schema-diff.py` - Python script which takes 2 schemas and attempts to resolve opcode changes automagically.

# Proposed Format for Opcode Lists

```json
[
  {
    "clientChannelName": 
      [
        { "someName": {  "opCode": 64, "version": 5110 } },
        { "someOtherName": { "opCode": 65, "version": 5110 } }
      ]
  },
  {
    "serverChannelName": 
      [
        { "someName": { "opCode": 64, "version": 5110 } },
        { "someOtherName": { "opCode": 65, "version": 5110 } }
      ]
  }
]
```
