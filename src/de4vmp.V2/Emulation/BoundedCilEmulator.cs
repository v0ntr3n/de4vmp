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

    private sealed record EmuType(TypeDefinition Type);
    private sealed record EmuMethodInfo(MethodDefinition Method);

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

                case CilCode.Add: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push(IsI64(a, b) ? (object)unchecked(ToI8(a) + ToI8(b)) : unchecked(ToI4(a) + ToI4(b)));
                    ip++; break;
                }
                case CilCode.Sub: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push(IsI64(a, b) ? (object)unchecked(ToI8(a) - ToI8(b)) : unchecked(ToI4(a) - ToI4(b)));
                    ip++; break;
                }
                case CilCode.Mul: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push(IsI64(a, b) ? (object)unchecked(ToI8(a) * ToI8(b)) : unchecked(ToI4(a) * ToI4(b)));
                    ip++; break;
                }
                case CilCode.Div: {
                    var b = Pop(stack); var a = Pop(stack);
                    if (IsI64(a, b)) {
                        long lb = ToI8(b), la = ToI8(a);
                        if (lb == 0 || (la == long.MinValue && lb == -1)) {
                            stopReason = "Division by zero or signed overflow in Div.";
                            return false;
                        }
                        stack.Push(la / lb);
                    }
                    else {
                        int ib = ToI4(b), ia = ToI4(a);
                        if (ib == 0 || (ia == int.MinValue && ib == -1)) {
                            stopReason = "Division by zero or signed overflow in Div.";
                            return false;
                        }
                        stack.Push(ia / ib);
                    }
                    ip++; break;
                }
                case CilCode.Div_Un: {
                    var b = Pop(stack); var a = Pop(stack);
                    if (IsI64(a, b)) {
                        ulong lb = ToU8(b), la = ToU8(a);
                        if (lb == 0) { stopReason = "Division by zero in Div_Un."; return false; }
                        stack.Push(unchecked((long)(la / lb)));
                    }
                    else {
                        uint ib = ToU4(b), ia = ToU4(a);
                        if (ib == 0) { stopReason = "Division by zero in Div_Un."; return false; }
                        stack.Push(unchecked((int)(ia / ib)));
                    }
                    ip++; break;
                }
                case CilCode.Rem: {
                    var b = Pop(stack); var a = Pop(stack);
                    if (IsI64(a, b)) {
                        long lb = ToI8(b), la = ToI8(a);
                        if (lb == 0 || (la == long.MinValue && lb == -1)) {
                            stopReason = "Division by zero or signed overflow in Rem.";
                            return false;
                        }
                        stack.Push(la % lb);
                    }
                    else {
                        int ib = ToI4(b), ia = ToI4(a);
                        if (ib == 0 || (ia == int.MinValue && ib == -1)) {
                            stopReason = "Division by zero or signed overflow in Rem.";
                            return false;
                        }
                        stack.Push(ia % ib);
                    }
                    ip++; break;
                }
                case CilCode.Rem_Un: {
                    var b = Pop(stack); var a = Pop(stack);
                    if (IsI64(a, b)) {
                        ulong lb = ToU8(b), la = ToU8(a);
                        if (lb == 0) { stopReason = "Division by zero in Rem_Un."; return false; }
                        stack.Push(unchecked((long)(la % lb)));
                    }
                    else {
                        uint ib = ToU4(b), ia = ToU4(a);
                        if (ib == 0) { stopReason = "Division by zero in Rem_Un."; return false; }
                        stack.Push(unchecked((int)(ia % ib)));
                    }
                    ip++; break;
                }
                case CilCode.Xor: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push(IsI64(a, b) ? (object)(ToI8(a) ^ ToI8(b)) : (ToI4(a) ^ ToI4(b)));
                    ip++; break;
                }
                case CilCode.And: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push(IsI64(a, b) ? (object)(ToI8(a) & ToI8(b)) : (ToI4(a) & ToI4(b)));
                    ip++; break;
                }
                case CilCode.Or: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push(IsI64(a, b) ? (object)(ToI8(a) | ToI8(b)) : (ToI4(a) | ToI4(b)));
                    ip++; break;
                }
                case CilCode.Shl: {
                    int b = ToI4(Pop(stack)); var a = Pop(stack);
                    stack.Push(IsI64(a) ? (object)(ToI8(a) << (b & 63)) : (ToI4(a) << (b & 31)));
                    ip++; break;
                }
                case CilCode.Shr: {
                    int b = ToI4(Pop(stack)); var a = Pop(stack);
                    stack.Push(IsI64(a) ? (object)(ToI8(a) >> (b & 63)) : (ToI4(a) >> (b & 31)));
                    ip++; break;
                }
                case CilCode.Shr_Un: {
                    int b = ToI4(Pop(stack)); var a = Pop(stack);
                    stack.Push(IsI64(a) ? (object)unchecked((long)(ToU8(a) >> (b & 63))) : unchecked((int)(ToU4(a) >> (b & 31))));
                    ip++; break;
                }
                case CilCode.Neg: {
                    var a = Pop(stack);
                    stack.Push(IsI64(a) ? (object)unchecked(-ToI8(a)) : unchecked(-ToI4(a)));
                    ip++; break;
                }
                case CilCode.Not: {
                    var a = Pop(stack);
                    stack.Push(IsI64(a) ? (object)(~ToI8(a)) : (~ToI4(a)));
                    ip++; break;
                }

                case CilCode.Conv_I1: stack.Push((int)(sbyte)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_U1: stack.Push((int)(byte)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_I2: stack.Push((int)(short)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_U2: stack.Push((int)(ushort)ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_I4:
                case CilCode.Conv_U4: stack.Push(ToI4(Pop(stack))); ip++; break;
                case CilCode.Conv_I8: { var v = Pop(stack); stack.Push(IsI64(v) ? ToI8(v) : (long)ToI4(v)); ip++; break; }
                case CilCode.Conv_U8: { var v = Pop(stack); stack.Push(IsI64(v) ? ToI8(v) : (long)(ulong)ToU4(v)); ip++; break; }

                case CilCode.Ceq: { var b = Pop(stack); var a = Pop(stack); stack.Push(AreEqual(a, b) ? 1 : 0); ip++; break; }
                case CilCode.Clt: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push((IsI64(a, b) ? ToI8(a) < ToI8(b) : ToI4(a) < ToI4(b)) ? 1 : 0);
                    ip++; break;
                }
                case CilCode.Clt_Un: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push((IsI64(a, b) ? ToU8(a) < ToU8(b) : ToU4(a) < ToU4(b)) ? 1 : 0);
                    ip++; break;
                }
                case CilCode.Cgt: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push((IsI64(a, b) ? ToI8(a) > ToI8(b) : ToI4(a) > ToI4(b)) ? 1 : 0);
                    ip++; break;
                }
                case CilCode.Cgt_Un: {
                    var b = Pop(stack); var a = Pop(stack);
                    stack.Push((IsI64(a, b) ? ToU8(a) > ToU8(b) : ToU4(a) > ToU4(b)) ? 1 : 0);
                    ip++; break;
                }

                case CilCode.Br:
                case CilCode.Br_S:
                    ip = ResolveLabel(insns, (ICilLabel)ins.Operand!);
                    break;

                case CilCode.Brfalse:
                case CilCode.Brfalse_S: {
                    var v = Pop(stack);
                    ip = IsZeroOrNull(v) ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Brtrue:
                case CilCode.Brtrue_S: {
                    var v = Pop(stack);
                    ip = !IsZeroOrNull(v) ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Beq:
                case CilCode.Beq_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    ip = AreEqual(a, b) ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bne_Un:
                case CilCode.Bne_Un_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    ip = !AreEqual(a, b) ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Blt:
                case CilCode.Blt_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToI8(a) < ToI8(b) : ToI4(a) < ToI4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bgt:
                case CilCode.Bgt_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToI8(a) > ToI8(b) : ToI4(a) > ToI4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Ble:
                case CilCode.Ble_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToI8(a) <= ToI8(b) : ToI4(a) <= ToI4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bge:
                case CilCode.Bge_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToI8(a) >= ToI8(b) : ToI4(a) >= ToI4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Blt_Un:
                case CilCode.Blt_Un_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToU8(a) < ToU8(b) : ToU4(a) < ToU4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bgt_Un:
                case CilCode.Bgt_Un_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToU8(a) > ToU8(b) : ToU4(a) > ToU4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Ble_Un:
                case CilCode.Ble_Un_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToU8(a) <= ToU8(b) : ToU4(a) <= ToU4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
                    break;
                }
                case CilCode.Bge_Un:
                case CilCode.Bge_Un_S: {
                    var b = Pop(stack); var a = Pop(stack);
                    bool cond = IsI64(a, b) ? ToU8(a) >= ToU8(b) : ToU4(a) >= ToU4(b);
                    ip = cond ? ResolveLabel(insns, (ICilLabel)ins.Operand!) : ip + 1;
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
                    else if (declName == "System.Object" && calleeName == ".ctor" && pCount == 0) {
                        // Allow System.Object::.ctor cleanly in instance constructors.
                    }
                    else if (declName == "System.Type" && calleeName == "GetTypeFromHandle" && pCount == 1) {
                        var td = callArgs[0] as TypeDefinition
                            ?? (callArgs[0] as ITypeDefOrRef)?.Resolve(method.DeclaringModule?.RuntimeContext);
                        stack.Push(td is not null ? new EmuType(td) : null);
                    }
                    else if (declName == "System.Type" && calleeName == "GetMethods" && pCount is 0 or 1 && receiver is EmuType emuType) {
                        // Default BindingFlags: Public (0x10) | Instance (0x04) | Static (0x08)
                        int flags = pCount == 1 ? ToI4(callArgs[0]) : (0x10 | 0x04 | 0x08);
                        bool wantInstance = (flags & 0x04) != 0;
                        bool wantStatic = (flags & 0x08) != 0;
                        bool wantPublic = (flags & 0x10) != 0;
                        bool wantNonPublic = (flags & 0x20) != 0;

                        var matched = emuType.Type.Methods
                            .Where(m => !m.IsConstructor &&
                                        (m.IsStatic ? wantStatic : wantInstance) &&
                                        (m.IsPublic ? wantPublic : wantNonPublic))
                            .ToList();

                        var arr = new EmuArray(matched.Count);
                        for (int mIdx = 0; mIdx < matched.Count; mIdx++)
                            arr.Elements[mIdx] = new EmuMethodInfo(matched[mIdx]);
                        stack.Push(arr);
                    }
                    else if (declName == "System.Delegate" && calleeName == "CreateDelegate" && pCount is >= 2 and <= 4) {
                        EmuType? delEmuType = callArgs[0] as EmuType;
                        EmuMethodInfo? targetMi = null;
                        bool boundToFirstArg = false;

                        if (pCount == 2 || (pCount == 3 && callArgs[1] is EmuMethodInfo)) {
                            targetMi = callArgs[1] as EmuMethodInfo;
                        }
                        else if (pCount >= 3 && callArgs[2] is EmuMethodInfo mi3) {
                            targetMi = mi3;
                            boundToFirstArg = callArgs[1] is not null;
                        }

                        if (delEmuType is not null && targetMi is not null &&
                            IsDelegateSignatureCompatible(delEmuType.Type, targetMi.Method, boundToFirstArg)) {
                            stack.Push(new EmuObject(delEmuType.Type.FullName) { DelegateTarget = targetMi.Method });
                        }
                        else {
                            stack.Push(null);
                        }
                    }
                    else if ((declName is "System.Reflection.MemberInfo" or "System.Reflection.MethodBase" or "System.Reflection.MethodInfo") &&
                             calleeName == "get_MetadataToken" && pCount == 0) {
                        int token = receiver switch {
                            EmuMethodInfo emi => emi.Method.MetadataToken.ToInt32(),
                            EmuType et => et.Type.MetadataToken.ToInt32(),
                            _ => 0
                        };
                        stack.Push(token);
                    }
                    else if (callee is MethodDefinition localMethod && localMethod.CilMethodBody is not null &&
                             localMethod.DeclaringType == method.DeclaringType &&
                             !localMethod.IsConstructor) {
                        var subArgs = hasThis ? new[] { receiver }.Concat(callArgs).ToArray() : callArgs;
                        if (!ExecuteFrame(localMethod, subArgs, staticFields, capturedHandlers, ref steps, depth + 1, out var subRet, out var subStop)) {
                            stopReason = subStop;
                            return false;
                        }
                        if (callee.Signature?.ReturnsValue == true)
                            stack.Push(subRet);
                    }
                    else {
                        stopReason = $"Unmodeled call: {callee.FullName}";
                        return false;
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

        stopReason = ip < 0
            ? "Unresolved branch target during bounded emulation."
            : "Execution fell off the end of method without ret.";
        return false;
    }

    private static bool IsZeroOrNull(object? v) => v switch {
        null => true,
        bool b => !b,
        int i => i == 0,
        uint u => u == 0,
        long l => l == 0,
        ulong ul => ul == 0,
        short s => s == 0,
        ushort us => us == 0,
        byte by => by == 0,
        sbyte sb => sb == 0,
        _ => false
    };

    private static object? Pop(Stack<object?> stack) => stack.Count > 0 ? stack.Pop() : 0;

    private static bool IsI64(object? a) => a is long or ulong;

    private static bool IsI64(object? a, object? b) => a is long or ulong || b is long or ulong;

    private static bool IsNumeric(object? v) =>
        v is int or uint or long or ulong or short or ushort or byte or sbyte or bool;

    private static bool AreEqual(object? a, object? b) {
        if (ReferenceEquals(a, b))
            return true;
        if (a is null || b is null)
            return false;
        if (IsNumeric(a) && IsNumeric(b))
            return IsI64(a, b) ? ToI8(a) == ToI8(b) : ToI4(a) == ToI4(b);
        return Equals(a, b);
    }

    private static int ToI4(object? v) => v switch {
        int i => i,
        uint u => unchecked((int)u),
        byte b => b,
        sbyte sb => sb,
        short s => s,
        ushort us => us,
        long l => unchecked((int)l),
        ulong ul => unchecked((int)ul),
        bool bl => bl ? 1 : 0,
        _ => 0
    };

    private static uint ToU4(object? v) => unchecked((uint)ToI4(v));

    private static long ToI8(object? v) => v switch {
        long l => l,
        ulong ul => unchecked((long)ul),
        int i => i,
        uint u => u,
        byte b => b,
        sbyte sb => sb,
        short s => s,
        ushort us => us,
        bool bl => bl ? 1L : 0L,
        _ => 0L
    };

    private static ulong ToU8(object? v) => v switch {
        ulong ul => ul,
        long l => unchecked((ulong)l),
        uint u => u,
        int i => unchecked((ulong)(uint)i),
        byte b => b,
        sbyte sb => unchecked((ulong)(uint)(int)sb),
        short s => unchecked((ulong)(uint)(int)s),
        ushort us => us,
        bool bl => bl ? 1UL : 0UL,
        _ => 0UL
    };

    private static int GetArgIndex(MethodDefinition method, object? operand) {
        if (operand is AsmResolver.DotNet.Collections.Parameter p) {
            // In AsmResolver 6.0.0, p.MethodSignatureIndex is the CIL argument slot (0 = 'this' for
            // instance methods, 1..N = declared parameters; 0..N-1 for static methods), whereas
            // p.Index is the 0-based index into method.Parameters (-1 for ThisParameter).
            return p.MethodSignatureIndex;
        }
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

    private static bool IsDelegateSignatureCompatible(TypeDefinition delType, MethodDefinition target, bool boundToFirstArg) {
        var invoke = delType.Methods.FirstOrDefault(m => m.Name == "Invoke");
        if (invoke?.Signature is null || target.Signature is null)
            return false;

        if (invoke.Signature.ReturnType.FullName != target.Signature.ReturnType.FullName)
            return false;

        var invokeParams = invoke.Signature.ParameterTypes;
        var targetParams = target.Signature.ParameterTypes;

        if (target.IsStatic || boundToFirstArg) {
            if (invokeParams.Count != targetParams.Count)
                return false;
            for (int i = 0; i < targetParams.Count; i++) {
                if (invokeParams[i].FullName != targetParams[i].FullName)
                    return false;
            }
            return true;
        }

        // Open instance delegate: Invoke(DeclaringType instance, ...targetParams)
        if (invokeParams.Count != targetParams.Count + 1)
            return false;
        string? declFullName = target.DeclaringType?.FullName;
        if (invokeParams[0].FullName != declFullName)
            return false;
        for (int i = 0; i < targetParams.Count; i++) {
            if (invokeParams[i + 1].FullName != targetParams[i].FullName)
                return false;
        }
        return true;
    }
}
