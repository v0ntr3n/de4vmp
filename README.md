# de4vmp

A fully static devirtualizer for VMProtect .NET (versions 3.4 and 3.5).

<img width="1904" height="573" alt="image" src="https://github.com/user-attachments/assets/b87fd449-d8fc-45a5-9b4a-f55a668a57a8" />

## How to build

Clone and build it yourself:

```bash
dotnet build -c Release
```

## How to use

1. Dump target via [KsDumper](https://github.com/EquiFox/KsDumper) if anti-tamper is present.
2. Demutate with [DeMutation](https://github.com/xlfj5211/DeMutation).
3. In CFF Explorer, ensure that the `ILOnly` flag is not set.
4. Clean it with de4dot so pattern detection actually works.
5. Drag and drop the cleaned file into the devirtualizer.
6. Clean the file with de4dot to remove junk.

## How it works

It runs a 3-stage pipeline:

1. **Function resolution:** Scans the .NET module for VM entry calls by matching specific CIL patterns.
2. **Handler resolution:** Locates the VM's handler table and maps the virtual opcodes to known CIL templates.
3. **Transformation:** Translates the virtual bytecode back into valid CIL and recompiles the method bodies.

## Troubleshooting

- **Demutation fails:** Anti-tamper is probably still active.
- **Devirtualization fails:** You are either targeting an unsupported version of VMProtect or the target is corrupted.

## Disclaimer

I made this a long time ago and left zero comments. Don't ask me how it works, because I honestly don't know either.
Huge thanks to [@Washi1337](https://github.com/Washi1337) for putting up with my never-ending stupid questions.