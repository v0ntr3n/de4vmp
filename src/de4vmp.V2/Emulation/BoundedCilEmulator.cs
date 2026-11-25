using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace de4vmp.V2.Emulation;

public sealed record EmulationSnapshot(
    IReadOnlyDictionary<uint, MethodDefinition> CapturedHandlers,
    IReadOnlyDictionary<string, object?> CapturedFields,
    object? ReturnValue,
    int StepsExecuted,
    bool CompletedNormally,
    string? StopReason);

/// <summary>
/// Pure-managed, sandboxed CIL interpreter with strict step budgets and allowlisted BCL hooks.
/// Never loads or executes target assemblies on the host CLR.
/// </summary>
public sealed class BoundedCilEmulator {
    private readonly int _maxSteps;
    private readonly int _maxCallDepth;

    public BoundedCilEmulator(int maxSteps = 250_000, int maxCallDepth = 8) {
        _maxSteps = maxSteps;
        _maxCallDepth = maxCallDepth;
    }

    private sealed class EmuObject {
        public string TypeName { get; }
        public Dictionary<string, object?> Fields { get; } = new(StringComparer.Ordinal);
        public Dictionary<uint, object?> DictEntries { get; } = new();
        public MethodDefinition? DelegateTarget { get; set; }

        public EmuObject(string typeName) => TypeName = typeName;
    }

    private sealed class EmuArray {
        public object?[] Elements { get; }
        public EmuArray(int length) => Elements = new object?[length];
    }

    public EmulationSnapshot EmulateMethod(
        MethodDefinition method,
        object?[]? initialArgs = null,
        Dictionary<string, object?>? staticFields = null,
        Dictionary<string, object?>? instanceFields = null) {
        var capturedHandlers = new Dictionary<uint, MethodDefinition>();
        var sFields = staticFields ?? new Dictionary<string, object?>(StringComparer.Ordinal);
        var thisObj = new EmuObject(method.DeclaringType?.FullName ?? "<This>");
        if (instanceFields is not null) {
            foreach (var (k, v) in instanceFields)
                thisObj.Fields[k] = v;
        }

        int totalArgs = (method.IsStatic ? 0 : 1) + method.Parameters.Count;
        var args = new object?[totalArgs];
        int offset = 0;
        if (!method.IsStatic) {
            args[0] = thisObj;
            offset = 1;
        }
        if (initialArgs is not null) {
            for (int i = 0; i < initialArgs.Length && offset + i < args.Length; i++)
                args[offset + i] = initialArgs[i];
        }

        int steps = 0;
        string? stopReason = null;
        object? retVal = null;
        bool completed = ExecuteFrame(method, args, sFields, capturedHandlers, ref steps, 0, out retVal, out stopReason);

        // Harvest any Delegate[] arrays stored on thisObj or staticFields
        foreach (var (_, val) in thisObj.Fields)
            HarvestArrayHandlers(val, capturedHandlers);
        foreach (var (_, val) in sFields)
            HarvestArrayHandlers(val, capturedHandlers);

        var mergedFields = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (k, v) in sFields) mergedFields[$"static::{k}"] = v;
        foreach (var (k, v) in thisObj.Fields) mergedFields[k] = v;

        return new EmulationSnapshot(capturedHandlers, mergedFields, retVal, steps, completed, stopReason);
    }

    private static void HarvestArrayHandlers(object? value, Dictionary<uint, MethodDefinition> capturedHandlers) {
        if (value is EmuArray arr) {
            for (int i = 0; i < arr.Elements.Length; i++) {
                if (arr.Elements[i] is EmuObject obj && obj.DelegateTarget is not null) {
                    capturedHandlers[(uint)i] = obj.DelegateTarget;
                }
            }
        }
        else if (value is EmuObject dict && dict.DictEntries.Count > 0) {
            foreach (var (k, v) in dict.DictEntries) {
                if (v is EmuObject dObj && dObj.DelegateTarget is not null) {
                    capturedHandlers[k] = dObj.DelegateTarget;
                }
            }
        }
    }

    private bool ExecuteFrame(
        MethodDefinition method,
        object?[] args,
        Dictionary<string, object?> staticFields,
        Dictionary<uint, MethodDefinition> capturedHandlers,
        ref int steps,
        int depth,
        out object? returnValue,
        out string? stopReason) {
        returnValue = null;
        stopReason = null;

        if (depth > _maxCallDepth) {
            stopReason = $"Exceeded max call depth ({_maxCallDepth}).";
            return false;
        }

        if (method.CilMethodBody is not { } body) {
            stopReason = $"Method {method.FullName} has no CIL body.";
            return false;
        }

        var insns = body.Instructions;
        insns.CalculateOffsets();
        var locals = new object?[body.LocalVariables.Count];
        var stack = new Stack<object?>();
        int ip = 0;

        while (ip >= 0 && ip < insns.Count) {
            if (++steps > _maxSteps) {
                stopReason = $"Exceeded emulation step budget ({_maxSteps}).";
                return false;
            }

            var ins = insns[ip];
            var code = ins.OpCode.Code;

            switch (code) {
                case CilCode.Nop:
                    ip++;
                    break;

                case CilCode.Ldc_I4:
                case CilCode.Ldc_I4_S:
                case CilCode.Ldc_I4_0:
                case CilCode.Ldc_I4_1:
                case CilCode.Ldc_I4_2:
                case CilCode.Ldc_I4_3:
                case CilCode.Ldc_I4_4:
                case CilCode.Ldc_I4_5:
                case CilCode.Ldc_I4_6:
                case CilCode.Ldc_I4_7:
                case CilCode.Ldc_I4_8:
                case CilCode.Ldc_I4_M1:
                    stack.Push(ins.GetLdcI4Constant());
                    ip++;
                    break;

                case CilCode.Ldc_I8:
                    stack.Push(Convert.ToInt64(ins.Operand));
                    ip++;
                    break;

                case CilCode.Ldnull:
                    stack.Push(null);
                    ip++;
                    break;

                case CilCode.Ldstr:
                    stack.Push(ins.Operand as string);
                    ip++;
                    break;

                case CilCode.Ldarg_0: stack.Push(args.Length > 0 ? args[0] : null); ip++; break;
                case CilCode.Ldarg_1: stack.Push(args.Length > 1 ? args[1] : null); ip++; break;
                case CilCode.Ldarg_2: stack.Push(args.Length > 2 ? args[2] : null); ip++; break;
                case CilCode.Ldarg_3: stack.Push(args.Length > 3 ? args[3] : null); ip++; break;
                case CilCode.Ldarg:
                case CilCode.Ldarg_S: {
                    int idx = GetArgIndex(method, ins.Operand);
                    stack.Push(idx >= 0 && idx < args.Length ? args[idx] : null);
                    ip++;
                    break;
                }

                case CilCode.Ldloc_0: stack.Push(locals[0]); ip++; break;
                case CilCode.Ldloc_1: stack.Push(locals[1]); ip++; break;
                case CilCode.Ldloc_2: stack.Push(locals[2]); ip++; break;
                case CilCode.Ldloc_3: stack.Push(locals[3]); ip++; break;
                case CilCode.Ldloc:
                case CilCode.Ldloc_S: {
                    int idx = ((CilLocalVariable)ins.Operand!).Index;
                    stack.Push(locals[idx]);
                    ip++;
                    break;
                }

                case CilCode.Stloc_0: locals[0] = Pop(stack); ip++; break;
                case CilCode.Stloc_1: locals[1] = Pop(stack); ip++; break;
                case CilCode.Stloc_2: locals[2] = Pop(stack); ip++; break;
                case CilCode.Stloc_3: locals[3] = Pop(stack); ip++; break;
                case CilCode.Stloc:
                case CilCode.Stloc_S: {
                    int idx = ((CilLocalVariable)ins.Operand!).Index;
                    locals[idx] = Pop(stack);
                    ip++;
                    break;
                }

                case CilCode.Dup: {
                    var top = stack.Count > 0 ? stack.Peek() : null;
                    stack.Push(top);
                    ip++;
                    break;
                }
                case CilCode.Pop:
                    Pop(stack);
                    ip++;
                    break;

                case CilCode.Add: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(unchecked(a + b)); ip++; break; }
                case CilCode.Sub: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(unchecked(a - b)); ip++; break; }
                case CilCode.Mul: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(unchecked(a * b)); ip++; break; }
                case CilCode.Div: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(b != 0 ? a / b : 0); ip++; break; }
                case CilCode.Div_Un: { uint b = ToU4(Pop(stack)); uint a = ToU4(Pop(stack)); stack.Push(b != 0 ? (int)(a / b) : 0); ip++; break; }
                case CilCode.Rem: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(b != 0 ? a % b : 0); ip++; break; }
                case CilCode.Rem_Un: { uint b = ToU4(Pop(stack)); uint a = ToU4(Pop(stack)); stack.Push(b != 0 ? (int)(a % b) : 0); ip++; break; }
                case CilCode.Xor: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(a ^ b); ip++; break; }
                case CilCode.And: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(a & b); ip++; break; }
                case CilCode.Or:  { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(a | b); ip++; break; }
                case CilCode.Shl: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(a << (b & 31)); ip++; break; }
                case CilCode.Shr: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(a >> (b & 31)); ip++; break; }
                case CilCode.Shr_Un: { int b = ToI4(Pop(stack)); uint a = ToU4(Pop(stack)); stack.Push((int)(a >> (b & 31))); ip++; break; }
                case CilCode.Neg: { int a = ToI4(Pop(stack)); stack.Push(unchecked(-a)); ip++; break; }
                case CilCode.Not: { int a = ToI4(Pop(stack)); stack.Push(~a); ip++; break; }

                case CilCode.Conv_I1: stack.Push((int)(sbyte)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_U1: stack.Push((int)(byte)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_I2: stack.Push((int)(short)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_U2: stack.Push((int)(ushort)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_I4:
                case CilCode.Conv_U4: stack.Push(ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_I8: stack.Push((long)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_U8: stack.Push((long)ToU4(Pop(stack))); ip++; break;

                case CilCode.Ceq: { var b = Pop(stack); var a = Pop(stack); stack.Push(Equals(a, b) ? 1 : 0); ip++; break; }
                case CilCode.Clt: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(a < b ? 1 : 0); ip++; break; }
                case CilCode.Clt_Un: { uint b = ToU4(Pop(stack)); uint a = ToU4(Pop(stack)); stack.Push(a < b ? 1 : 0); ip++; break; }
                case CilCode.Cgt: { int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack)); stack.Push(a > b ? 1 : 0); ip++; break; }
                case CilCode.Cgt_Un: { uint b = ToU4(Pop(stack)); uint a = ToU4(Pop(stack)); stack.Push(a > b ? 1 : 0); ip++; break; }

                case CilCode.Br:
                case CilCode.Br_S:
                    ip = ResolveLabel(insns, (ICilLabel)ins.Operand!);
                    break;

                case CilCode.Brfalse:
                case CilCode.Brfalse_S: {
                    var v = Pop(stack);
                    bool isFalse = v is null || (v is int i && i == 0) || (v is bool b && !b) || (v is long l && l == 0);
                    ip = isFalse ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Brtrue:
                case CilCode.Brtrue_S: {
                    var v = Pop(stack);
                    bool isTrue = v is not null && !((v is int i && i == 0) || (v is bool b && !b) || (v is long l && l == 0));
                    ip = isTrue ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Beq:
                case CilCode.Beq_S: {
                    int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack));
                    ip = a == b ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bne_Un:
                case CilCode.Bne_Un_S: {
                    int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack));
                    ip = a != b ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Blt:
                case CilCode.Blt_S: {
                    int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack));
                    ip = a < b ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bgt:
                case CilCode.Bgt_S: {
                    int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack));
                    ip = a > b ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Ble:
                case CilCode.Ble_S: {
                    int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack));
                    ip = a <= b ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bge:
                case CilCode.Bge_S: {
                    int b = ToI4(Pop(stack)); int a = ToI4(Pop(stack));
                    ip = a >= b ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Switch: {
                    uint idx = ToU4(Pop(stack));
                    var targets = (IList<ICilLabel>)ins.Operand!;
                    ip = idx < targets.Count ? ResolveLabel(insns, targets[(int)idx]) : ip + 1;
                    break;
                }

                case CilCode.Newarr: {
                    int len = Math.Clamp(ToI4(Pop(stack)), 0, 1_000_000);
                    stack.Push(new EmuArray(len));
                    ip++;
                    break;
                }
                case CilCode.Ldlen: {
                    var arr = Pop(stack) as EmuArray;
                    stack.Push(arr?.Elements.Length ?? 0);
                    ip++;
                    break;
                }
                case CilCode.Stelem_Ref:
                case CilCode.Stelem_I4:
                case CilCode.Stelem_I1: {
                    var val = Pop(stack);
                    int idx = ToI4(Pop(stack));
                    if (Pop(stack) is EmuArray arr && idx >= 0 && idx < arr.Elements.Length)
                        arr.Elements[idx] = val;
                    ip++;
                    break;
                }
                case CilCode.Ldelem_Ref:
                case CilCode.Ldelem_I4:
                case CilCode.Ldelem_U1: {
                    int idx = ToI4(Pop(stack));
                    object? val = null;
                    if (Pop(stack) is EmuArray arr && idx >= 0 && idx < arr.Elements.Length)
                        val = arr.Elements[idx];
                    stack.Push(val);
                    ip++;
                    break;
                }

                case CilCode.Ldftn:
                    stack.Push(ins.Operand as IMethodDescriptor);
                    ip++;
                    break;

                case CilCode.Ldtoken:
                    stack.Push(ins.Operand);
                    ip++;
                    break;

                case CilCode.Ldfld: {
                    var obj = Pop(stack) as EmuObject;
                    string fname = ((IFieldDescriptor)ins.Operand!).Name ?? string.Empty;
                    stack.Push(obj is not null && obj.Fields.TryGetValue(fname, out var v) ? v : null);
                    ip++;
                    break;
                }
                case CilCode.Stfld: {
                    var val = Pop(stack);
                    var obj = Pop(stack) as EmuObject;
                    string fname = ((IFieldDescriptor)ins.Operand!).Name ?? string.Empty;
                    if (obj is not null) obj.Fields[fname] = val;
                    ip++;
                    break;
                }
                case CilCode.Ldsfld: {
                    string fname = ((IFieldDescriptor)ins.Operand!).Name ?? string.Empty;
                    stack.Push(staticFields.TryGetValue(fname, out var v) ? v : null);
                    ip++;
                    break;
                }
                case CilCode.Stsfld: {
                    var val = Pop(stack);
                    string fname = ((IFieldDescriptor)ins.Operand!).Name ?? string.Empty;
                    staticFields[fname] = val;
                    ip++;
                    break;
                }

                case CilCode.Box:
                case CilCode.Unbox_Any:
                case CilCode.Castclass:
                case CilCode.Isinst:
                    ip++;
                    break;

                case CilCode.Newobj: {
                    var ctor = (IMethodDescriptor)ins.Operand!;
                    int pCount = ctor.Signature?.ParameterTypes.Count ?? 0;
                    var callArgs = new object?[pCount];
                    for (int k = pCount - 1; k >= 0; k--)
                        callArgs[k] = Pop(stack);

                    string typeName = ctor.DeclaringType?.FullName ?? "<Unknown>";
                    var created = new EmuObject(typeName);

                    // Delegate constructor: (object target, IntPtr methodPtr)
                    if (pCount == 2 && callArgs[1] is IMethodDescriptor targetMethod) {
                        created.DelegateTarget = targetMethod as MethodDefinition
                            ?? targetMethod.Resolve(method.DeclaringModule?.RuntimeContext);
                    }

                    stack.Push(created);
                    ip++;
                    break;
                }

                case CilCode.Call:
                case CilCode.Callvirt: {
                    var callee = (IMethodDescriptor)ins.Operand!;
                    int pCount = callee.Signature?.ParameterTypes.Count ?? 0;
                    bool hasThis = callee.Signature?.HasThis ?? false;
                    var callArgs = new object?[pCount];
                    for (int k = pCount - 1; k >= 0; k--)
                        callArgs[k] = Pop(stack);
                    object? receiver = hasThis ? Pop(stack) : null;

                    string calleeName = callee.Name ?? string.Empty;
                    string declName = callee.DeclaringType?.FullName ?? string.Empty;

                    // Allowlisted BCL hooks
                    if (declName.StartsWith("System.Collections.Generic.Dictionary`2", StringComparison.Ordinal) &&
                        (calleeName == "Add" || calleeName == "set_Item") &&
                        pCount == 2 && receiver is EmuObject dictObj) {
                        uint key = ToU4(callArgs[0]);
                        dictObj.DictEntries[key] = callArgs[1];
                        if (callArgs[1] is EmuObject delObj && delObj.DelegateTarget is not null) {
                            capturedHandlers[key] = delObj.DelegateTarget;
                        }
                    }
                    else if (declName == "System.Runtime.CompilerServices.RuntimeHelpers" &&
                             calleeName == "InitializeArray" && pCount == 2 &&
                             callArgs[0] is EmuArray targetArr &&
                             callArgs[1] is FieldDefinition { FieldRva: { } rvaSegment }) {
                        byte[] raw = rvaSegment.WriteIntoArray();
                        for (int b = 0; b < Math.Min(raw.Length, targetArr.Elements.Length); b++)
                            targetArr.Elements[b] = (int)raw[b];
                    }
                    else if (callee is MethodDefinition localMethod && localMethod.CilMethodBody is not null &&
                             localMethod.DeclaringType == method.DeclaringType &&
                             !localMethod.IsConstructor) {
                        var subArgs = hasThis ? new[] { receiver }.Concat(callArgs).ToArray() : callArgs;
                        ExecuteFrame(localMethod, subArgs, staticFields, capturedHandlers, ref steps, depth + 1, out var subRet, out _);
                        if (callee.Signature?.ReturnsValue == true)
                            stack.Push(subRet);
                    }
                    else {
                        if (callee.Signature?.ReturnsValue == true)
                            stack.Push(0);
                    }

                    ip++;
                    break;
                }

                case CilCode.Ret:
                    returnValue = stack.Count > 0 ? stack.Pop() : null;
                    return true;

                default:
                    stopReason = $"Unsupported CIL opcode during bounded emulation: {code}";
                    return false;
            }
        }

        return true;
    }

    private static object? Pop(Stack<object?> stack) => stack.Count > 0 ? stack.Pop() : 0;

    private static int ToI4(object? v) => v switch {
        int i => i,
        uint u => unchecked((int)u),
        byte b => b,
        sbyte sb => sb,
        short s => s,
        ushort us => us,
        long l => unchecked((int)l),
        bool bl => bl ? 1 : 0,
        _ => 0
    };

    private static uint ToU4(object? v) => unchecked((uint)ToI4(v));

    private static int GetArgIndex(MethodDefinition method, object? operand) {
        if (operand is AsmResolver.DotNet.Collections.Parameter p)
            return p.MethodSignatureIndex;
        return 0;
    }

    private static int ResolveLabel(CilInstructionCollection insns, ICilLabel label) {
        if (label is CilInstructionLabel il && il.Instruction is not null)
            return insns.IndexOf(il.Instruction);
        for (int i = 0; i < insns.Count; i++) {
            if (insns[i].Offset == label.Offset)
                return i;
        }
        return -1;
    }
}
