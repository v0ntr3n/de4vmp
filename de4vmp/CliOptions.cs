namespace de4vmp;

internal static class ExitCodes {
    public const int Success = 0;
    public const int UnexpectedError = 1;
    public const int InvalidArguments = 2;
    public const int DevirtualizationError = 3;
    public const int Timeout = 124;
}

internal sealed class CliOptions {
    public string? InputPath { get; init; }
    public string? OutputPath { get; init; }
    public bool NonInteractive { get; init; }
    public bool NoBanner { get; init; }
    public bool ShowHelp { get; init; }
    public bool ShowVersion { get; init; }
    public TimeSpan? Timeout { get; init; }

    public static bool TryParse(string[] args, out CliOptions options, out string? error) {
        string? inputPath = null;
        string? outputPath = null;
        bool nonInteractive = IsCiEnvironment();
        bool noBanner = false;
        bool showHelp = false;
        bool showVersion = false;
        TimeSpan? timeout = TryGetEnvTimeout(out string? envError);

        if (envError is not null) {
            options = new CliOptions { NonInteractive = nonInteractive };
            error = envError;
            return false;
        }

        for (int i = 0; i < args.Length; i++) {
            string arg = args[i];

            switch (arg) {
                case "-h":
                case "--help":
                    showHelp = true;
                    break;

                case "-v":
                case "--version":
                    showVersion = true;
                    break;

                case "--ci":
                case "--non-interactive":
                case "--no-pause":
                    nonInteractive = true;
                    break;

                case "--no-banner":
                    noBanner = true;
                    break;

                case "-i":
                case "--input":
                    if (i + 1 >= args.Length) {
                        options = new CliOptions { NonInteractive = nonInteractive };
                        error = $"Missing value for {arg}.";
                        return false;
                    }

                    inputPath = args[++i];
                    break;

                case "-o":
                case "--output":
                    if (i + 1 >= args.Length) {
                        options = new CliOptions { NonInteractive = nonInteractive };
                        error = $"Missing value for {arg}.";
                        return false;
                    }

                    outputPath = args[++i];
                    break;

                case "-t":
                case "--timeout":
                    if (i + 1 >= args.Length) {
                        options = new CliOptions { NonInteractive = nonInteractive };
                        error = $"Missing value for {arg}.";
                        return false;
                    }

                    string rawTimeout = args[++i];
                    if (!int.TryParse(rawTimeout, out int seconds) || seconds < 0) {
                        options = new CliOptions { NonInteractive = nonInteractive };
                        error = $"Invalid timeout '{rawTimeout}'. Specify a non-negative integer number of seconds (0 disables timeout).";
                        return false;
                    }

                    timeout = seconds == 0 ? null : TimeSpan.FromSeconds(seconds);
                    break;

                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal)) {
                        options = new CliOptions { NonInteractive = nonInteractive };
                        error = $"Unknown option: {arg}. Use --help to see available options.";
                        return false;
                    }

                    if (inputPath is not null) {
                        options = new CliOptions { NonInteractive = nonInteractive };
                        error = $"Unexpected extra argument: {arg}. Only one input file may be specified.";
                        return false;
                    }

                    inputPath = arg;
                    break;
            }
        }

        options = new CliOptions {
            InputPath = inputPath,
            OutputPath = outputPath,
            NonInteractive = nonInteractive,
            NoBanner = noBanner,
            ShowHelp = showHelp,
            ShowVersion = showVersion,
            Timeout = timeout
        };

        error = null;
        return true;
    }

    public static bool IsInteractiveSession(bool nonInteractiveFlag) {
        if (nonInteractiveFlag)
            return false;

        if (Console.IsInputRedirected || Console.IsOutputRedirected)
            return false;

        return true;
    }

    public static string GetUsage() =>
        """
        Usage:
          de4vmp [options] <input-file>
          de4vmp --input <input-file> [options]

        Options:
          -i, --input <path>        Path to the target .NET PE file to devirtualize.
          -o, --output <path>       Optional output file path (default: <name>_devirtualized<ext>).
          -t, --timeout <seconds>   Maximum execution time in seconds (0 disables timeout).
                                    Can also be set via DE4VMP_TIMEOUT_SECONDS.
              --ci, --non-interactive
                                    Disable interactive prompts (auto-enabled in CI or redirected I/O).
              --no-banner           Suppress the ASCII art banner.
          -v, --version             Display version information and exit.
          -h, --help                Display this help message and exit.

        Exit Codes:
          0    Success
          1    Unexpected error
          2    Invalid arguments or invalid input/output path
          3    Devirtualization error (unsupported or invalid target)
          124  Execution timed out
        """;

    private static bool IsCiEnvironment() {
        return IsTruthyEnv("CI") || IsTruthyEnv("GITHUB_ACTIONS") || IsTruthyEnv("DE4VMP_CI");
    }

    private static bool IsTruthyEnv(string name) {
        string? value = Environment.GetEnvironmentVariable(name);
        return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "1", StringComparison.OrdinalIgnoreCase);
    }

    private static TimeSpan? TryGetEnvTimeout(out string? error) {
        string? raw = Environment.GetEnvironmentVariable("DE4VMP_TIMEOUT_SECONDS");
        if (string.IsNullOrWhiteSpace(raw)) {
            error = null;
            return null;
        }

        if (!int.TryParse(raw, out int seconds) || seconds < 0) {
            error = $"Invalid DE4VMP_TIMEOUT_SECONDS value '{raw}'. Expected a non-negative integer.";
            return null;
        }

        error = null;
        return seconds == 0 ? null : TimeSpan.FromSeconds(seconds);
    }
}
