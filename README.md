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
5. Drag and drop the cleaned file into the devirtualizer, or run it from the command line.
6. Clean the file with de4dot to remove junk.

### Command-line & Headless CI Usage

`de4vmp` supports both interactive drag-and-drop execution and non-interactive headless execution for CI/CD pipelines.

```bash
de4vmp [options] <input-file>
de4vmp --input <input-file> [--output <output-file>] [--timeout <seconds>] --ci
```

| Option | Description |
| --- | --- |
| `-i`, `--input <path>` | Path to the target `.NET` PE file (also accepted as a positional argument). |
| `-o`, `--output <path>` | Optional output path (defaults to `<name>_devirtualized<ext>`). |
| `-t`, `--timeout <seconds>` | Maximum execution time in seconds (`0` disables timeout). Also configurable via `DE4VMP_TIMEOUT_SECONDS`. |
| `--ci`, `--non-interactive` | Disables interactive prompts (`Press any key to continue...`). Automatically enabled when `CI=true`, `GITHUB_ACTIONS=true`, `DE4VMP_CI=true`, or when stdin/stdout is redirected. |
| `--no-banner` | Suppresses the ASCII art banner. |
| `-v`, `--version` | Prints version information and exits. |
| `-h`, `--help` | Prints usage information and exits. |

#### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success (or `--help` / `--version`) |
| `1` | Unexpected error |
| `2` | Invalid CLI arguments, invalid path, or non-.NET PE input |
| `3` | Devirtualization failure (`DevirtualizationException`) |
| `124` | Execution timed out |

## GitHub Actions CI

This fork includes automated GitHub Actions workflows targeting **Windows x64** on **.NET 7.0**:

- **Build (`build.yml`)** — Restores dependencies with NuGet caching, builds the solution in `Release` mode, publishes a self-contained single-file Windows x64 executable (`de4vmp.exe`) with `SHA256SUMS.txt`, and uploads it as the `de4vmp-win-x64` artifact.
- **Smoke Test (`smoke-test.yml`)** — Builds the Windows x64 executable, compiles a self-authored `.NET 7` dummy fixture on the fly (never executing it), validates CLI flags, argument validation, static analysis startup, stdout/stderr capture, and exit codes, and uploads diagnostic logs (`de4vmp-smoke-test-diagnostics`) even on failure.

### Triggering workflows manually

```bash
gh workflow run build.yml
gh workflow run smoke-test.yml -f timeout_seconds=30
```

Compiled Windows x64 binaries can be downloaded from the **Artifacts** section of any completed `Build (Windows x64)` workflow run.

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