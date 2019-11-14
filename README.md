# FFXIVOpcodes
A shared effort to maintain FFXIV opcode mappings

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
