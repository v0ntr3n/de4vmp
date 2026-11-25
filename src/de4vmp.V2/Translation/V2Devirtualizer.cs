using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;
using de4vmp.V2.Analysis;
using de4vmp.V2.Emulation;
using de4vmp.V2.Models;
using de4vmp.V2.Semantics;

namespace de4vmp.V2.Translation;

/// <summary>
/// Clean-room V2 managed VM devirtualizer built on AsmResolver 6.0.0.
/// Pipeline:
///   1. Structural VM runtime discovery (8-bit Delegate[] and 32-bit-keyed Dictionary&lt;uint, Delegate&gt;).
///   2. Bounded sandboxed CIL emulation of .cctor/.ctor (zero host-CLR execution) to materialize handler map + bytecode.
///   3. CFF unflattening + fail-closed semantic handler classification.
///   4. Verified VM entry call-site resolution (both (object[], int) and multi-entry (object, int) stubs).
///   5. Bytecode stream decoding (including rolling-key decryption) + clean CIL &amp; EH reconstruction.
/// </summary>
public sealed class V2Devirtualizer {
    private readonly CffUnflattener _unflattener = new();
    private readonly BoundedCilEmulator _emulator = new();
    private readonly HandlerSemanticClassifier _classifier;

    public V2Devirtualizer() {
        _classifier = new HandlerSemanticClassifier(_unflattener, _emulator);
    }

    public DevirtualizationMetrics Devirtualize(ModuleDefinition module) {
        var diagnostics = new List<string>();
        var discovery = DiscoverVm(module, diagnostics);
        if (discovery is null) {
            diagnostics.Add("No supported managed VM runtime found in module.");
            return new DevirtualizationMetrics(0, 0, 0, 0, 0, 0, new Dictionary<uint, ResolvedHandler>(), diagnostics);
        }

        int totalSwitchesEliminated = 0;
        var resolvedHandlers = new Dictionary<uint, ResolvedHandler>();
        foreach (var (key, method) in discovery.RawHandlers) {
            var resolved = _classifier.Classify(key, method, out int switches);
            totalSwitchesEliminated += switches;
            resolvedHandlers[key] = resolved;
        }

        int classifiedCount = resolvedHandlers.Values.Count(h => h.SemanticOp != SemanticOp.Unknown);
        int unknownCount = resolvedHandlers.Count - classifiedCount;

        var callSites = FindVerifiedCallSites(module, discovery);
        int devirtualizedCount = 0;

        foreach (var site in callSites) {
            if (TryRecompileMethod(module, discovery, resolvedHandlers, site, diagnostics)) {
                devirtualizedCount++;
            }
        }

        return new DevirtualizationMetrics(
            MethodsDiscovered: callSites.Count,
            MethodsDevirtualized: devirtualizedCount,
            HandlersDiscovered: resolvedHandlers.Count,
            HandlersClassified: classifiedCount,
            UnknownHandlers: unknownCount,
            CffSwitchesEliminated: totalSwitchesEliminated,
            Handlers: resolvedHandlers,
            Diagnostics: diagnostics);
    }

    public VmDiscoveryResult? DiscoverVm(ModuleDefinition module, List<string> diagnostics) {
        foreach (var type in module.GetAllTypes()) {
            bool hasUIntDict = type.Fields.Any(f =>
                f.Signature?.FieldType.FullName.StartsWith("System.Collections.Generic.Dictionary`2<System.UInt32,", StringComparison.Ordinal) == true);
            bool hasDelegateArray = type.Fields.Any(f =>
                f.Signature?.FieldType is SzArrayTypeSignature arr &&
                arr.BaseType.ToTypeDefOrRef() is TypeDefinition td && td.IsDelegate);

            if (!hasUIntDict && !hasDelegateArray)
                continue;

            var entryMethods = type.Methods
                .Where(IsSupportedVmEntry)
                .ToList();

            if (entryMethods.Count == 0)
                continue;

            var staticFields = new Dictionary<string, object?>(StringComparer.Ordinal);
            var handlers = new Dictionary<uint, MethodDefinition>();
            int totalSteps = 0;

            var cctor = type.GetStaticConstructor();
            if (cctor?.CilMethodBody is not null) {
                var cctorSnap = _emulator.EmulateMethod(cctor, staticFields: staticFields);
                totalSteps += cctorSnap.StepsExecuted;
                foreach (var (k, v) in cctorSnap.CapturedHandlers)
                    handlers[k] = v;
            }

            foreach (var ctor in type.Methods.Where(m => m.IsConstructor && !m.IsStatic && m.CilMethodBody is not null)) {
                var ctorSnap = _emulator.EmulateMethod(ctor, staticFields: staticFields);
                totalSteps += ctorSnap.StepsExecuted;
                foreach (var (k, v) in ctorSnap.CapturedHandlers)
                    handlers[k] = v;
            }

            if (handlers.Count == 0) {
                diagnostics.Add($"Candidate VM type {type.FullName} yielded 0 handlers after bounded emulation ({totalSteps} steps).");
                continue;
            }

            // Extract embedded bytecode blob and optional rolling-key parameters from static fields / FieldRva
            byte[] blob = ExtractBytecodeBlob(type);
            uint keySeed = ExtractStaticUIntField(type, "KeySeed", staticFields);
            uint keyStep = ExtractStaticUIntField(type, "KeyStep", staticFields);

            return new VmDiscoveryResult(
                type,
                entryMethods,
                handlers,
                blob,
                keySeed,
                keyStep,
                hasUIntDict,
                totalSteps);
        }

        return null;
    }

    private static bool IsSupportedVmEntry(MethodDefinition m) {
        if (!m.IsPublic || m.IsStatic || m.Parameters.Count != 2)
            return false;
        if (m.Signature?.ReturnType.FullName != "System.Object")
            return false;
        string p0 = m.Parameters[0].ParameterType.FullName;
        string p1 = m.Parameters[1].ParameterType.FullName;
        return (p0 == "System.Object[]" || p0 == "System.Object") && p1 == "System.Int32";
    }

    private static byte[] ExtractBytecodeBlob(TypeDefinition vmType) {
        // 1. Check embedded ManifestResource ("VmBytecode")
        if (vmType.DeclaringModule is { } mod) {
            var res = mod.Resources.FirstOrDefault(r => r.Name == "VmBytecode");
            if (res?.GetData() is { Length: > 0 } resData)
                return resData;
        }
        // 2. Check FieldRva-backed static field
        foreach (var field in vmType.Fields) {
            if (field.FieldRva is { } seg) {
                byte[] bytes = seg.WriteIntoArray();
                if (bytes.Length > 0) return bytes;
            }
        }
        // 3. Check .cctor for ldtoken <rvaField> + RuntimeHelpers.InitializeArray
        var cctor = vmType.GetStaticConstructor();
        if (cctor?.CilMethodBody is { } body) {
            foreach (var ins in body.Instructions) {
                if (ins.OpCode.Code == CilCode.Ldtoken && ins.Operand is FieldDefinition { FieldRva: { } seg }) {
                    byte[] bytes = seg.WriteIntoArray();
                    if (bytes.Length > 0) return bytes;
                }
            }
        }
        return Array.Empty<byte>();
    }

    private static uint ExtractStaticUIntField(TypeDefinition vmType, string name, Dictionary<string, object?> staticFields) {
        if (staticFields.TryGetValue(name, out var v)) {
            return v switch {
                int i => unchecked((uint)i),
                uint u => u,
                _ => 0u
            };
        }
        var f = vmType.Fields.FirstOrDefault(x => x.Name == name);
        if (f?.Constant?.Value?.Data is { Length: >= 4 } bytes)
            return BitConverter.ToUInt32(bytes, 0);
        return 0u;
    }

    private static List<VerifiedCallSite> FindVerifiedCallSites(ModuleDefinition module, VmDiscoveryResult vm) {
        var entrySet = new HashSet<MethodDefinition>(vm.EntryMethods);
        var sites = new List<VerifiedCallSite>();

        foreach (var type in module.GetAllTypes()) {
            if (type == vm.VmType)
                continue;
            foreach (var method in type.Methods) {
                if (method.CilMethodBody is not { } body)
                    continue;
                var insns = body.Instructions;
                for (int i = 1; i < insns.Count; i++) {
                    if (insns[i].OpCode.Code is not (CilCode.Call or CilCode.Callvirt))
                        continue;
                    if (insns[i].Operand is not MethodDefinition callee || !entrySet.Contains(callee))
                        continue;
                    if (!insns[i - 1].IsLdcI4())
                        continue;

                    int offset = insns[i - 1].GetLdcI4Constant();
                    // Verify offset actually points within the discovered bytecode blob
                    if (vm.BytecodeBlob.Length > 0 && (offset < 0 || offset >= vm.BytecodeBlob.Length))
                        continue;

                    sites.Add(new VerifiedCallSite(method, callee, i, offset));
                    break;
                }
            }
        }

        return sites;
    }

    private static bool TryRecompileMethod(
        ModuleDefinition module,
        VmDiscoveryResult vm,
        IReadOnlyDictionary<uint, ResolvedHandler> handlers,
        VerifiedCallSite site,
        List<string> diagnostics) {
        byte[] decoded = DecryptBytecode(vm.BytecodeBlob, vm.RollingKeySeed, vm.RollingKeyStep);
        if (site.BytecodeOffset < 0 || site.BytecodeOffset + 8 > decoded.Length) {
            diagnostics.Add($"Method {site.Caller.FullName}: invalid bytecode offset {site.BytecodeOffset}.");
            return false;
        }

        using var ms = new MemoryStream(decoded, site.BytecodeOffset, decoded.Length - site.BytecodeOffset, writable: false);
        using var br = new BinaryReader(ms);

        // Method header: [int32 localCount][int32 insnCount][int32 ehCount]
        int localCount = br.ReadInt32();
        int insnCount = br.ReadInt32();
        int ehCount = br.ReadInt32();

        if (localCount < 0 || localCount > 256 || insnCount <= 0 || insnCount > 10_000 || ehCount < 0 || ehCount > 64) {
            diagnostics.Add($"Method {site.Caller.FullName}: malformed virtual method header.");
            return false;
        }

        var vOps = new List<(SemanticOp Op, int Operand)>(insnCount);
        for (int i = 0; i < insnCount; i++) {
            uint key = vm.Is32BitKeyed ? br.ReadUInt32() : br.ReadByte();
            if (!handlers.TryGetValue(key, out var handler) || handler.SemanticOp == SemanticOp.Unknown) {
                // Fail-closed: never emit partial/guessed IL when a handler is Unknown!
                diagnostics.Add($"Method {site.Caller.FullName}: unknown/unverified handler key 0x{key:X8} at vIP {i}.");
                return false;
            }

            int operand = HasInt32Operand(handler.SemanticOp) ? br.ReadInt32() : 0;
            vOps.Add((handler.SemanticOp, operand));
        }

        var ehSpecs = new List<(int Kind, int TryStart, int TryEnd, int HandlerStart, int HandlerEnd, int CatchTypeToken)>(ehCount);
        for (int i = 0; i < ehCount; i++) {
            ehSpecs.Add((br.ReadInt32(), br.ReadInt32(), br.ReadInt32(), br.ReadInt32(), br.ReadInt32(), br.ReadInt32()));
        }

        // Rebuild clean CilMethodBody
        var newBody = new CilMethodBody { InitializeLocals = true };
        var corlib = module.CorLibTypeFactory;

        // Infer local types (default int32; upgrade to object/type if NewObj/LdArg/Catch stores non-int32 into StLoc)
        var localTypes = Enumerable.Repeat<TypeSignature>(corlib.Int32, localCount).ToArray();
        for (int i = 1; i < vOps.Count; i++) {
            if (vOps[i].Op == SemanticOp.StLoc && vOps[i].Operand >= 0 && vOps[i].Operand < localCount) {
                var prev = vOps[i - 1];
                if (prev.Op == SemanticOp.NewObj && TryLookupMember(module, prev.Operand) is IMethodDescriptor ctor && ctor.DeclaringType is not null) {
                    localTypes[vOps[i].Operand] = new TypeDefOrRefSignature(ctor.DeclaringType.ToTypeDefOrRef(), isValueType: false);
                }
                else if (prev.Op == SemanticOp.LdArg && prev.Operand >= 0 && prev.Operand < site.Caller.Parameters.Count) {
                    localTypes[vOps[i].Operand] = site.Caller.Parameters[prev.Operand].ParameterType;
                }
            }
        }
        foreach (var eh in ehSpecs) {
            if (eh.Kind == 0 && eh.CatchTypeToken != 0 && eh.HandlerStart >= 0 && eh.HandlerStart < vOps.Count &&
                vOps[eh.HandlerStart].Op == SemanticOp.StLoc &&
                vOps[eh.HandlerStart].Operand >= 0 && vOps[eh.HandlerStart].Operand < localCount &&
                TryLookupMember(module, eh.CatchTypeToken) is ITypeDefOrRef catchType) {
                localTypes[vOps[eh.HandlerStart].Operand] = new TypeDefOrRefSignature(catchType, isValueType: false);
            }
        }

        for (int i = 0; i < localCount; i++)
            newBody.LocalVariables.Add(new CilLocalVariable(localTypes[i]));

        // Map virtual instruction index -> first emitted CIL instruction
        var vIndexToCil = new CilInstruction[vOps.Count + 1];
        var pendingBranches = new List<(CilInstruction Insn, int TargetVIndex)>();

        for (int i = 0; i < vOps.Count; i++) {
            var (op, operand) = vOps[i];
            int startIdx = newBody.Instructions.Count;

            switch (op) {
                case SemanticOp.Nop: newBody.Instructions.Add(CilOpCodes.Nop); break;
                case SemanticOp.LdcI4: newBody.Instructions.Add(CilOpCodes.Ldc_I4, operand); break;
                case SemanticOp.LdArg:
                    newBody.Instructions.Add(CilOpCodes.Ldarg, site.Caller.Parameters[operand]);
                    break;
                case SemanticOp.LdLoc:
                    newBody.Instructions.Add(CilOpCodes.Ldloc, newBody.LocalVariables[operand]);
                    break;
                case SemanticOp.StLoc:
                    newBody.Instructions.Add(CilOpCodes.Stloc, newBody.LocalVariables[operand]);
                    break;
                case SemanticOp.Add: newBody.Instructions.Add(CilOpCodes.Add); break;
                case SemanticOp.Sub: newBody.Instructions.Add(CilOpCodes.Sub); break;
                case SemanticOp.Mul: newBody.Instructions.Add(CilOpCodes.Mul); break;
                case SemanticOp.Div: newBody.Instructions.Add(CilOpCodes.Div); break;
                case SemanticOp.Rem: newBody.Instructions.Add(CilOpCodes.Rem); break;
                case SemanticOp.Xor: newBody.Instructions.Add(CilOpCodes.Xor); break;
                case SemanticOp.And: newBody.Instructions.Add(CilOpCodes.And); break;
                case SemanticOp.Or:  newBody.Instructions.Add(CilOpCodes.Or); break;
                case SemanticOp.Shl: newBody.Instructions.Add(CilOpCodes.Shl); break;
                case SemanticOp.Shr: newBody.Instructions.Add(CilOpCodes.Shr); break;
                case SemanticOp.Neg: newBody.Instructions.Add(CilOpCodes.Neg); break;
                case SemanticOp.Ceq: newBody.Instructions.Add(CilOpCodes.Ceq); break;
                case SemanticOp.Clt: newBody.Instructions.Add(CilOpCodes.Clt); break;
                case SemanticOp.Cgt: newBody.Instructions.Add(CilOpCodes.Cgt); break;
                case SemanticOp.Br: {
                    var brInsn = new CilInstruction(CilOpCodes.Br, new CilInstructionLabel());
                    newBody.Instructions.Add(brInsn);
                    pendingBranches.Add((brInsn, operand));
                    break;
                }
                case SemanticOp.BrTrue: {
                    var brInsn = new CilInstruction(CilOpCodes.Brtrue, new CilInstructionLabel());
                    newBody.Instructions.Add(brInsn);
                    pendingBranches.Add((brInsn, operand));
                    break;
                }
                case SemanticOp.BrFalse: {
                    var brInsn = new CilInstruction(CilOpCodes.Brfalse, new CilInstructionLabel());
                    newBody.Instructions.Add(brInsn);
                    pendingBranches.Add((brInsn, operand));
                    break;
                }
                case SemanticOp.Ret: newBody.Instructions.Add(CilOpCodes.Ret); break;
                case SemanticOp.NewObj:
                    newBody.Instructions.Add(CilOpCodes.Newobj, (IMethodDescriptor)TryLookupMember(module, operand)!);
                    break;
                case SemanticOp.LdFld:
                    newBody.Instructions.Add(CilOpCodes.Ldfld, (IFieldDescriptor)TryLookupMember(module, operand)!);
                    break;
                case SemanticOp.StFld:
                    newBody.Instructions.Add(CilOpCodes.Stfld, (IFieldDescriptor)TryLookupMember(module, operand)!);
                    break;
                case SemanticOp.Call:
                    newBody.Instructions.Add(CilOpCodes.Call, (IMethodDescriptor)TryLookupMember(module, operand)!);
                    break;
                case SemanticOp.CallVirt:
                    newBody.Instructions.Add(CilOpCodes.Callvirt, (IMethodDescriptor)TryLookupMember(module, operand)!);
                    break;
                case SemanticOp.LdElemI4: newBody.Instructions.Add(CilOpCodes.Ldelem_I4); break;
                case SemanticOp.StElemI4: newBody.Instructions.Add(CilOpCodes.Stelem_I4); break;
                case SemanticOp.LdLen:
                    newBody.Instructions.Add(CilOpCodes.Ldlen);
                    newBody.Instructions.Add(CilOpCodes.Conv_I4);
                    break;
                case SemanticOp.Leave: {
                    var lvInsn = new CilInstruction(CilOpCodes.Leave, new CilInstructionLabel());
                    newBody.Instructions.Add(lvInsn);
                    pendingBranches.Add((lvInsn, operand));
                    break;
                }
                case SemanticOp.EndFinally: newBody.Instructions.Add(CilOpCodes.Endfinally); break;
                default:
                    diagnostics.Add($"Method {site.Caller.FullName}: unhandled SemanticOp {op}.");
                    return false;
            }

            vIndexToCil[i] = newBody.Instructions[startIdx];
        }

        // Wire branch labels
        foreach (var (insn, targetIdx) in pendingBranches) {
            if (targetIdx < 0 || targetIdx >= vOps.Count) {
                diagnostics.Add($"Method {site.Caller.FullName}: branch target {targetIdx} out of range.");
                return false;
            }
            insn.Operand = vIndexToCil[targetIdx].CreateLabel();
        }

        // Wire ECMA-335 Exception Handlers
        foreach (var eh in ehSpecs) {
            var cilEh = new CilExceptionHandler {
                HandlerType = eh.Kind == 0 ? CilExceptionHandlerType.Exception : CilExceptionHandlerType.Finally,
                TryStart = vIndexToCil[eh.TryStart].CreateLabel(),
                TryEnd = vIndexToCil[eh.TryEnd].CreateLabel(),
                HandlerStart = vIndexToCil[eh.HandlerStart].CreateLabel(),
                HandlerEnd = eh.HandlerEnd < vOps.Count
                    ? vIndexToCil[eh.HandlerEnd].CreateLabel()
                    : newBody.Instructions.EndLabel
            };
            if (eh.Kind == 0 && eh.CatchTypeToken != 0) {
                cilEh.ExceptionType = (ITypeDefOrRef)TryLookupMember(module, eh.CatchTypeToken)!;
            }
            newBody.ExceptionHandlers.Add(cilEh);
        }

        newBody.Instructions.OptimizeMacros();
        newBody.Instructions.CalculateOffsets();
        site.Caller.CilMethodBody = newBody;
        newBody.ComputeMaxStack();
        return true;
    }

    private static IMetadataMember? TryLookupMember(ModuleDefinition module, int token) =>
        module.LookupMember(new MetadataToken((uint)token));

    private static bool HasInt32Operand(SemanticOp op) => op is
        SemanticOp.LdcI4 or SemanticOp.LdArg or SemanticOp.LdLoc or SemanticOp.StLoc or
        SemanticOp.Br or SemanticOp.BrTrue or SemanticOp.BrFalse or SemanticOp.Leave or
        SemanticOp.NewObj or SemanticOp.LdFld or SemanticOp.StFld or SemanticOp.Call or SemanticOp.CallVirt;

    private static byte[] DecryptBytecode(byte[] raw, uint seed, uint step) {
        if (seed == 0 && step == 0)
            return raw;

        byte[] output = new byte[raw.Length];
        uint key = seed;
        for (int i = 0; i < raw.Length; i++) {
            output[i] = (byte)(raw[i] ^ (key & 0xFF));
            key = unchecked(key + step);
        }
        return output;
    }
}
