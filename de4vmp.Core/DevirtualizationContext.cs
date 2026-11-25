using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Serialized;
using AsmResolver.PE.File;
using de4vmp.Core.Architecture;
using de4vmp.Core.Services;
using de4vmp.Core.Translation.Resolution;

namespace de4vmp.Core;

public class DevirtualizationContext {
    private readonly IDictionary<uint, VmpFunction> _functions = new Dictionary<uint, VmpFunction>();
    
    private readonly IDictionary<byte, HandlerBase> _handlers = new Dictionary<byte, HandlerBase>();

    public DevirtualizationContext(IReadOnlyList<string> args)
        : this(ValidateSingleArg(args), null) {
    }

    public DevirtualizationContext(string inputPath, string? outputPath = null) {
        if (string.IsNullOrWhiteSpace(inputPath))
            throw new ArgumentException("Invalid arguments, please specify path to target.", nameof(inputPath));

        string filePath = Path.GetFullPath(inputPath);
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            throw new ArgumentException($"Invalid path, file does not exist: {inputPath}", nameof(inputPath));

        InputPath = filePath;
        OutputPath = string.IsNullOrWhiteSpace(outputPath) ? null : Path.GetFullPath(outputPath);

        PeFile = PEFile.FromFile(filePath);
        var dataDirectory = PeFile.OptionalHeader.DataDirectories[(short)DataDirectoryIndex.ClrDirectory];
        if (!dataDirectory.IsPresentInPE)
            throw new ArgumentException("PEFile does not have dotnet metadata! This devirtualizer is for .NET!");

        string? workingDirectory = Path.GetDirectoryName(filePath);
        if (string.IsNullOrEmpty(workingDirectory))
            workingDirectory = Directory.GetCurrentDirectory();

        var readerParameters = new ModuleReaderParameters(workingDirectory, EmptyErrorListener.Instance);
        Module = ModuleDefinition.FromFile(PeFile, readerParameters);
    }

    private static string ValidateSingleArg(IReadOnlyList<string> args) {
        if (args.Count != 1)
            throw new ArgumentException("Invalid arguments, please specify path to target.");

        return args[0];
    }
    
    public void ImportFunction(VmpFunction function) {
        if (_functions.TryAdd(function.Rva, function))
            return;

        throw ExceptionService.ThrowInferredException(function, nameof(function));
    }
    
    public bool TryLookupFunction(uint address, out VmpFunction function) {
        return _functions.TryGetValue(address, out function!);
    }
    
    public void ImportHandler(byte opCodeValue, HandlerBase handler) {
        if (_handlers.TryAdd(opCodeValue, handler))
            return;
        
        throw ExceptionService.ThrowInferredException(handler, nameof(handler));
    }
    
    public bool TryLookupHandler(byte opCodeValue, out HandlerBase handler) {
        return _handlers.TryGetValue(opCodeValue, out handler!);
    }

    public string InputPath { get; }

    public string? OutputPath { get; }

    public PEFile PeFile { get; }

    public ModuleDefinition Module { get; }

    public IEnumerable<VmpFunction> Functions => _functions.Values;
}