using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using de4vmp.Core.Architecture;

namespace de4vmp.Core.Services; 

public static class FunctionService {
    public static IEnumerable<VmpFunction> ResolveFunctions(IEnumerable<MethodDefinition> methods) {
        foreach (var methodDefinition in methods) {
            var cilMethodBody = methodDefinition.CilMethodBody;
            if (cilMethodBody is null)
                continue;

            var instructions = cilMethodBody.Instructions;
            for (int i = 0; i < instructions.Count; i++) {
                var instruction = instructions[i];
                if (instruction.OpCode.Code != CilCode.Call || !ResolveVirtualMachineEntry(instruction))
                    continue;

                if (i == 0)
                    continue;
                var constantInstruction = instructions[i - 1];
                if (constantInstruction.OpCode.Code != CilCode.Ldc_I4)
                    continue;

                uint rva = (uint) constantInstruction.GetLdcI4Constant();
                yield return new VmpFunction(methodDefinition, rva);
            }
        }
    }

    // These are only structural candidates. They must not be passed to the
    // legacy decoder until the VM entry and bytecode format are verified.
    public static IEnumerable<(MethodDefinition Caller, MethodDefinition Entry, uint Operand)>
        FindUInt32VmCandidates(IEnumerable<MethodDefinition> methods) {
        foreach (var caller in methods) {
            var instructions = caller.CilMethodBody?.Instructions;
            if (instructions is null) continue;
            for (int i = 1; i < instructions.Count; i++) {
                var call = instructions[i];
                if (call.OpCode.Code is not (CilCode.Call or CilCode.Callvirt) ||
                    call.Operand is not MethodDefinition entry || !entry.IsPublic || entry.IsStatic ||
                    entry.Signature is null || !entry.Signature.ReturnType.IsFullnameType(typeof(object)) ||
                    entry.Parameters.Count != 2 ||
                    !entry.Parameters[0].ParameterType.IsFullnameType(typeof(object)) ||
                    !entry.Parameters[1].ParameterType.IsFullnameType(typeof(int)) ||
                    entry.DeclaringType is not { } type ||
                    !type.Fields.Any(f => f.Signature?.FieldType.FullName.StartsWith(
                        "System.Collections.Generic.Dictionary`2<System.UInt32, ", StringComparison.Ordinal) == true) ||
                    !instructions[i - 1].IsLdcI4())
                    continue;
                yield return (caller, entry, unchecked((uint)instructions[i - 1].GetLdcI4Constant()));
            }
        }
    }
    
    private static bool ResolveVirtualMachineEntry(CilInstruction instruction) {
        if (instruction.Operand is not MethodDefinition methodDefinition)
            return false;

        var parameters = methodDefinition.Parameters;
        
        if (!methodDefinition.IsPublic || methodDefinition.IsStatic || parameters.Count != 2)
            return false;

        if (methodDefinition.Signature is { } signature && !signature.ReturnType.IsFullnameType(typeof(object)))
            return false;

        return parameters[0].ParameterType.IsFullnameType(typeof(object[])) &&
               parameters[1].ParameterType.IsFullnameType(typeof(int));
    }
}
