using de4vmp.Core.Services;

namespace de4vmp.Core.Pipeline.Phases; 

public class FunctionResolutionPhase : IPhase {
    public void Run(ILogger logger, DevirtualizationContext context) {
        logger.Information(this, "Searching for functions...");
        
        var methods = context.Module.GetAllTypes()
            .SelectMany(typeDefinition => typeDefinition.Methods).ToArray();
        var functions = FunctionService.ResolveFunctions(methods).ToArray();

        foreach (var function in functions) {
            context.ImportFunction(function);
            logger.Debug(this, $"Function: {function.Parent}, RVA: {function.Rva}");
        }
        if (functions.Length == 0) {
            var candidates = FunctionService.FindUInt32VmCandidates(methods).ToArray();
            if (candidates.Length > 0)
                logger.Warning(this, $"Found {candidates.Length} possible 32-bit VM entry call sites; " +
                    "these are unverified candidates and the 32-bit VM is not supported.");
        }
    }
}
