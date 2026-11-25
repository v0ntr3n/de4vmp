using System.Diagnostics;
using System.Reflection;
using de4vmp;
using de4vmp.Core;
using Figgle;
using Spectre.Console;

var stdoutConsole = AnsiConsole.Create(new AnsiConsoleSettings {
    Out = new AnsiConsoleOutput(Console.Out)
});
var stderrConsole = AnsiConsole.Create(new AnsiConsoleSettings {
    Out = new AnsiConsoleOutput(Console.Error)
});

if (!CliOptions.TryParse(args, out var options, out string? parseError)) {
    Console.Error.WriteLine($"Error: {parseError}");
    Console.Error.WriteLine();
    Console.Error.WriteLine(CliOptions.GetUsage());
    return ExitCodes.InvalidArguments;
}

if (options.ShowHelp) {
    Console.Out.WriteLine(CliOptions.GetUsage());
    return ExitCodes.Success;
}

(string productName, string version, string companyName) = GetVersionMetadata();

if (options.ShowVersion) {
    Console.Out.WriteLine($"{productName} {version} ({companyName})");
    return ExitCodes.Success;
}

bool isInteractive = CliOptions.IsInteractiveSession(options.NonInteractive);

if (isInteractive) {
    try {
        Console.Title = $"{productName} - {version} | {companyName}";
    }
    catch (IOException) {
        // Ignore when no console window handle is attached.
    }
    catch (PlatformNotSupportedException) {
        // Ignore on platforms that do not support Console.Title.
    }
}

if (!options.NoBanner) {
    RenderBanner(stdoutConsole, isInteractive);
}

const string tag = nameof(de4vmp);

if (string.IsNullOrWhiteSpace(options.InputPath)) {
    Console.Error.WriteLine("Error: Missing input file path. Use --help for usage.");
    PauseIfInteractive(stdoutConsole, isInteractive);
    return ExitCodes.InvalidArguments;
}

if (!TryValidatePaths(options.InputPath, options.OutputPath, out string resolvedInput, out string? resolvedOutput, out string? pathError)) {
    Console.Error.WriteLine($"Error: {pathError}");
    PauseIfInteractive(stdoutConsole, isInteractive);
    return ExitCodes.InvalidArguments;
}

var stopwatch = Stopwatch.StartNew();
var logger = new ConsoleLogger(stdoutConsole, stopwatch);
int exitCode = ExitCodes.Success;

try {
    logger.Information(tag, "Started devirtualization...");
    if (options.Timeout is { } configuredTimeout) {
        logger.Information(tag, $"Execution timeout set to {configuredTimeout.TotalSeconds:0}s.");
    }

    using var cts = options.Timeout is { } timeout
        ? new CancellationTokenSource(timeout)
        : new CancellationTokenSource();

    var workTask = Task.Run(() => {
        cts.Token.ThrowIfCancellationRequested();
        var context = new DevirtualizationContext(resolvedInput, resolvedOutput);
        var devirtualizer = new Devirtualizer(logger);
        devirtualizer.Devirtualize(context, cts.Token);
    }, cts.Token);

    if (options.Timeout is { } limit) {
        var delayTask = Task.Delay(limit);
        var finished = Task.WhenAny(workTask, delayTask).GetAwaiter().GetResult();
        if (finished != workTask) {
            cts.Cancel();
            Console.Error.WriteLine($"Error: Devirtualization timed out after {limit.TotalSeconds:0} seconds.");
            exitCode = ExitCodes.Timeout;
        }
        else {
            workTask.GetAwaiter().GetResult();
        }
    }
    else {
        workTask.GetAwaiter().GetResult();
    }
}
catch (OperationCanceledException) {
    Console.Error.WriteLine("Error: Devirtualization was cancelled due to timeout.");
    exitCode = ExitCodes.Timeout;
}
catch (ArgumentException exception) {
    stderrConsole.WriteException(exception);
    exitCode = ExitCodes.InvalidArguments;
}
catch (BadImageFormatException exception) {
    stderrConsole.WriteException(exception);
    exitCode = ExitCodes.InvalidArguments;
}
catch (DevirtualizationException exception) {
    stderrConsole.WriteException(exception);
    exitCode = ExitCodes.DevirtualizationError;
}
catch (Exception exception) {
    stderrConsole.WriteException(exception);
    Console.Error.WriteLine("Something went wrong! Please submit a bug report at the repository.");
    exitCode = ExitCodes.UnexpectedError;
}
finally {
    stopwatch.Stop();
    logger.Information(tag, $"Finished devirtualization in {stopwatch.ElapsedMilliseconds} Milliseconds...");
}

PauseIfInteractive(stdoutConsole, isInteractive);
return exitCode;

static (string ProductName, string Version, string CompanyName) GetVersionMetadata() {
    var assembly = Assembly.GetExecutingAssembly();
    string productName = assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product ?? nameof(de4vmp);
    string companyName = assembly.GetCustomAttribute<AssemblyCompanyAttribute>()?.Company ?? "chramiq";
    string version = assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    try {
        string? location = Environment.ProcessPath;

        if (!string.IsNullOrEmpty(location) && File.Exists(location)) {
            var versionInfo = FileVersionInfo.GetVersionInfo(location);
            if (!string.IsNullOrWhiteSpace(versionInfo.ProductName))
                productName = versionInfo.ProductName;
            if (!string.IsNullOrWhiteSpace(versionInfo.FileVersion))
                version = versionInfo.FileVersion;
            if (!string.IsNullOrWhiteSpace(versionInfo.CompanyName))
                companyName = versionInfo.CompanyName;
        }
    }
    catch {
        // Fall back to assembly attributes when file version info is unavailable.
    }

    return (productName, version, companyName);
}

static void RenderBanner(IAnsiConsole console, bool isInteractive) {
    byte r = byte.MaxValue, g = byte.MaxValue, b = byte.MaxValue;
    int width = 80;
    if (isInteractive) {
        try {
            if (Console.WindowWidth > 0)
                width = Console.WindowWidth;
        }
        catch (IOException) {
            // Use default width when console window width is unavailable.
        }
    }

    var font = FiggleFonts.SlantSmall;
    string banner = font.Render(nameof(de4vmp));
    foreach (string line in banner.Split(Environment.NewLine)) {
        int pad = Math.Max(line.Length, width / 2 + line.Length / 2);
        console.WriteLine(line.PadLeft(pad), new Style(new Color(r -= 27, g -= 18, b -= 9)));
    }
}

static bool TryValidatePaths(
    string inputPath,
    string? outputPath,
    out string resolvedInput,
    out string? resolvedOutput,
    out string? error) {
    resolvedInput = string.Empty;
    resolvedOutput = null;

    try {
        resolvedInput = Path.GetFullPath(inputPath);
    }
    catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) {
        error = $"Invalid input path '{inputPath}': {ex.Message}";
        return false;
    }

    if (Directory.Exists(resolvedInput)) {
        error = $"Input path is a directory, expected a file: {resolvedInput}";
        return false;
    }

    if (!File.Exists(resolvedInput)) {
        error = $"Input file does not exist: {resolvedInput}";
        return false;
    }

    if (!string.IsNullOrWhiteSpace(outputPath)) {
        try {
            resolvedOutput = Path.GetFullPath(outputPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) {
            error = $"Invalid output path '{outputPath}': {ex.Message}";
            return false;
        }

        if (Directory.Exists(resolvedOutput)) {
            error = $"Output path is an existing directory, expected a file path: {resolvedOutput}";
            return false;
        }
    }

    error = null;
    return true;
}

static void PauseIfInteractive(IAnsiConsole console, bool isInteractive) {
    if (!isInteractive)
        return;

    console.WriteLine("Press any key to continue...");
    Console.ReadKey();
}
