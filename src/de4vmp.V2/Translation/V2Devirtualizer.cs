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

            // Structurally discover bytecode blob and optional rolling-key parameters without relying on hardcoded names
            var candidateOffsets = CollectCandidateCallSiteOffsets(module, type, entryMethods);
            var (blob, keySeed, keyStep) = ExtractBytecodeAndKeys(type, staticFields, handlers, hasUIntDict, candidateOffsets);

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

    private static (byte[] Blob, uint KeySeed, uint KeyStep) ExtractBytecodeAndKeys(
        TypeDefinition vmType,
        Dictionary<string, object?> staticFields,
        IReadOnlyDictionary<uint, MethodDefinition> handlers,
        bool is32BitKeyed,
        IReadOnlyList<int> candidateOffsets) {
        var candidateBlobs = CollectCandidateBlobs(vmType);
        if (candidateBlobs.Count == 0)
            return (Array.Empty<byte>(), 0u, 0u);

        var candidateKeyPairs = CollectCandidateKeyPairs(vmType, staticFields);
        var offsetsToProbe = candidateOffsets.Count > 0 ? candidateOffsets : [0];
        int keySize = is32BitKeyed ? 4 : 1;

        byte[]? bestBlob = null;
        uint bestSeed = 0u;
        uint bestStep = 0u;
        int bestScore = 0;

        foreach (var blob in candidateBlobs) {
            foreach (var (seed, step) in candidateKeyPairs) {
                byte[] decoded = DecryptBytecode(blob, seed, step);
                int score = ScoreDecodedBlob(decoded, offsetsToProbe, handlers, is32BitKeyed, keySize);
                if (score > bestScore) {
                    bestScore = score;
                    bestBlob = blob;
                    bestSeed = seed;
                    bestStep = step;
                }
            }
        }

        if (bestBlob is not null)
            return (bestBlob, bestSeed, bestStep);

        // Fallback when no candidate fully validates (e.g. truncated bytecode): return first structural blob candidate
        return (candidateBlobs[0], 0u, 0u);
    }

    private static List<byte[]> CollectCandidateBlobs(TypeDefinition vmType) {
        var nonStandardResources = new List<byte[]>();
        var standardResources = new List<byte[]>();
        var rvaBlobs = new List<byte[]>();

        if (vmType.DeclaringModule is { } mod) {
            foreach (var res in mod.Resources) {
                if (res.GetData() is not { Length: > 0 } data)
                    continue;
                string name = res.Name ?? string.Empty;
                if (name.EndsWith(".g.resources", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase)) {
                    standardResources.Add(data);
                }
                else {
                    nonStandardResources.Add(data);
                }
            }
        }

        foreach (var field in vmType.Fields) {
            if (field.FieldRva is { } seg) {
                byte[] bytes = seg.WriteIntoArray();
                if (bytes.Length > 0)
                    rvaBlobs.Add(bytes);
            }
        }

        var cctor = vmType.GetStaticConstructor();
        if (cctor?.CilMethodBody is { } body) {
            foreach (var ins in body.Instructions) {
                if (ins.OpCode.Code == CilCode.Ldtoken && ins.Operand is FieldDefinition { FieldRva: { } seg }) {
                    byte[] bytes = seg.WriteIntoArray();
                    if (bytes.Length > 0)
                        rvaBlobs.Add(bytes);
                }
            }
        }

        var result = new List<byte[]>(nonStandardResources.Count + rvaBlobs.Count + standardResources.Count);
        result.AddRange(nonStandardResources);
        result.AddRange(rvaBlobs);
        result.AddRange(standardResources);
        return result;
    }

    private static List<(uint Seed, uint Step)> CollectCandidateKeyPairs(
        TypeDefinition vmType,
        Dictionary<string, object?> staticFields) {
        var values = new List<uint>();
        var seen = new HashSet<uint>();

        static void AddCandidate(uint v, List<uint> list, HashSet<uint> seenSet) {
            if (v != 0 && seenSet.Add(v))
                list.Add(v);
        }

        foreach (var (_, v) in staticFields) {
            if (v is int i) AddCandidate(unchecked((uint)i), values, seen);
            else if (v is uint u) AddCandidate(u, values, seen);
        }

        foreach (var field in vmType.Fields) {
            if (!field.IsStatic)
                continue;
            string? fType = field.Signature?.FieldType.FullName;
            if (fType is not ("System.UInt32" or "System.Int32"))
                continue;
            if (field.Constant?.Value?.Data is { Length: >= 4 } bytes)
                AddCandidate(BitConverter.ToUInt32(bytes, 0), values, seen);
        }

        var pairs = new List<(uint Seed, uint Step)> { (0u, 0u) };
        for (int i = 0; i < values.Count; i++) {
            pairs.Add((values[i], 0u));
            for (int j = 0; j < values.Count; j++) {
                if (i != j)
                    pairs.Add((values[i], values[j]));
            }
        }
        return pairs;
    }

    private static int ScoreDecodedBlob(
        byte[] decoded,
        IReadOnlyList<int> offsets,
        IReadOnlyDictionary<uint, MethodDefinition> handlers,
        bool is32BitKeyed,
        int keySize) {
        int score = 0;
        foreach (int offset in offsets) {
            if (offset < 0 || offset + 12 + keySize > decoded.Length)
                continue;

            int localCount = BitConverter.ToInt32(decoded, offset);
            int insnCount = BitConverter.ToInt32(decoded, offset + 4);
            int ehCount = BitConverter.ToInt32(decoded, offset + 8);
            if (localCount < 0 || localCount > 256 || insnCount <= 0 || insnCount > 10_000 || ehCount < 0 || ehCount > 64)
                continue;

            uint firstKey = is32BitKeyed
                ? BitConverter.ToUInt32(decoded, offset + 12)
                : decoded[offset + 12];
            if (handlers.ContainsKey(firstKey))
                score++;
        }
        return score;
    }

    private static List<int> CollectCandidateCallSiteOffsets(
        ModuleDefinition module,
        TypeDefinition vmType,
        IReadOnlyList<MethodDefinition> entryMethods) {
        var entrySet = new HashSet<MethodDefinition>(entryMethods);
        var offsets = new List<int>();
        foreach (var type in module.GetAllTypes()) {
            if (type == vmType)
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
                    if (TryEvaluatePrecedingConstantInt32(insns, i, out int offset) && offset >= 0) {
                        offsets.Add(offset);
                        break;
                    }
                }
            }
        }
        return offsets;
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
                    if (!TryEvaluatePrecedingConstantInt32(insns, i, out int offset))
                        continue;

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

    /// <summary>
    /// Evaluates a pure-constant integer expression immediately preceding <paramref name="callIndex"/>
    /// (e.g. `ldc.i4 X`, `ldc.i4 A; ldc.i4 B; xor`, or arbitrary nested pure arithmetic/bitwise expressions).
    /// </summary>
    private static bool TryEvaluatePrecedingConstantInt32(CilInstructionCollection insns, int callIndex, out int value) {
        value = 0;
        int needed = 1;
        int startIdx = -1;
        int minIdx = Math.Max(0, callIndex - 64);

        for (int k = callIndex - 1; k >= minIdx; k--) {
            var ins = insns[k];
            var code = ins.OpCode.Code;
            if (code == CilCode.Nop) {
                continue;
            }
            if (ins.IsLdcI4()) {
                needed -= 1;
            }
            else if (code is CilCode.Neg or CilCode.Not or CilCode.Conv_I1 or CilCode.Conv_U1
                or CilCode.Conv_I2 or CilCode.Conv_U2 or CilCode.Conv_I4 or CilCode.Conv_U4) {
                // Unary: consumes 1, produces 1 -> needed unchanged
            }
            else if (code is CilCode.Add or CilCode.Sub or CilCode.Mul or CilCode.Div or CilCode.Div_Un
                or CilCode.Rem or CilCode.Rem_Un or CilCode.Xor or CilCode.And or CilCode.Or
                or CilCode.Shl or CilCode.Shr or CilCode.Shr_Un
                or CilCode.Ceq or CilCode.Clt or CilCode.Clt_Un or CilCode.Cgt or CilCode.Cgt_Un) {
                needed += 1;
            }
            else if (code == CilCode.Dup && needed >= 2) {
                needed -= 1;
            }
            else {
                return false;
            }

            if (needed == 0) {
                startIdx = k;
                break;
            }
        }

        if (startIdx < 0)
            return false;

        // Guard against control-flow merges: reject if any branch targets an interior instruction or callIndex itself.
        for (int i = 0; i < insns.Count; i++) {
            if (insns[i].Operand is ICilLabel lbl) {
                int target = ResolveLabelIndex(insns, lbl);
                if (target > startIdx && target <= callIndex)
                    return false;
            }
            else if (insns[i].Operand is IList<ICilLabel> targets) {
                foreach (var t in targets) {
                    int target = ResolveLabelIndex(insns, t);
                    if (target > startIdx && target <= callIndex)
                        return false;
                }
            }
        }

        var eval = new Stack<int>();
        for (int k = startIdx; k < callIndex; k++) {
            var ins = insns[k];
            var code = ins.OpCode.Code;
            if (code == CilCode.Nop)
                continue;
            if (ins.IsLdcI4()) {
                eval.Push(ins.GetLdcI4Constant());
                continue;
            }
            if (code == CilCode.Dup) {
                if (eval.Count < 1) return false;
                eval.Push(eval.Peek());
                continue;
            }
            if (code is CilCode.Neg or CilCode.Not or CilCode.Conv_I1 or CilCode.Conv_U1
                or CilCode.Conv_I2 or CilCode.Conv_U2 or CilCode.Conv_I4 or CilCode.Conv_U4) {
                if (eval.Count < 1) return false;
                int a = eval.Pop();
                eval.Push(code switch {
                    CilCode.Neg => unchecked(-a),
                    CilCode.Not => ~a,
                    CilCode.Conv_I1 => (sbyte)a,
                    CilCode.Conv_U1 => (byte)a,
                    CilCode.Conv_I2 => (short)a,
                    CilCode.Conv_U2 => (ushort)a,
                    _ => a
                });
                continue;
            }

            if (eval.Count < 2)
                return false;
            int b = eval.Pop();
            int lhs = eval.Pop();
            switch (code) {
                case CilCode.Add: eval.Push(unchecked(lhs + b)); break;
                case CilCode.Sub: eval.Push(unchecked(lhs - b)); break;
                case CilCode.Mul: eval.Push(unchecked(lhs * b)); break;
                case CilCode.Div:
                    if (b == 0 || (lhs == int.MinValue && b == -1)) return false;
                    eval.Push(lhs / b);
                    break;
                case CilCode.Div_Un:
                    if (b == 0) return false;
                    eval.Push(unchecked((int)((uint)lhs / (uint)b)));
                    break;
                case CilCode.Rem:
                    if (b == 0 || (lhs == int.MinValue && b == -1)) return false;
                    eval.Push(lhs % b);
                    break;
                case CilCode.Rem_Un:
                    if (b == 0) return false;
                    eval.Push(unchecked((int)((uint)lhs % (uint)b)));
                    break;
                case CilCode.Xor: eval.Push(lhs ^ b); break;
                case CilCode.And: eval.Push(lhs & b); break;
                case CilCode.Or:  eval.Push(lhs | b); break;
                case CilCode.Shl: eval.Push(lhs << (b & 31)); break;
                case CilCode.Shr: eval.Push(lhs >> (b & 31)); break;
                case CilCode.Shr_Un: eval.Push(unchecked((int)((uint)lhs >> (b & 31)))); break;
                case CilCode.Ceq: eval.Push(lhs == b ? 1 : 0); break;
                case CilCode.Clt: eval.Push(lhs < b ? 1 : 0); break;
                case CilCode.Clt_Un: eval.Push((uint)lhs < (uint)b ? 1 : 0); break;
                case CilCode.Cgt: eval.Push(lhs > b ? 1 : 0); break;
                case CilCode.Cgt_Un: eval.Push((uint)lhs > (uint)b ? 1 : 0); break;
                default: return false;
            }
        }

        if (eval.Count != 1)
            return false;

        value = eval.Pop();
        return true;
    }

    private static bool TryRecompileMethod(
        ModuleDefinition module,
        VmDiscoveryResult vm,
        IReadOnlyDictionary<uint, ResolvedHandler> handlers,
        VerifiedCallSite site,
        List<string> diagnostics) {
        byte[] decoded = DecryptBytecode(vm.BytecodeBlob, vm.RollingKeySeed, vm.RollingKeyStep);
        if (site.BytecodeOffset < 0 || site.BytecodeOffset + 12 > decoded.Length) {
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

        int keySize = vm.Is32BitKeyed ? 4 : 1;
        var vOps = new List<(SemanticOp Op, int Operand)>(insnCount);
        for (int i = 0; i < insnCount; i++) {
            if (ms.Length - ms.Position < keySize) {
                diagnostics.Add($"Method {site.Caller.FullName}: truncated bytecode stream reading opcode at vIP {i}.");
                return false;
            }
            uint key = vm.Is32BitKeyed ? br.ReadUInt32() : br.ReadByte();
            if (!handlers.TryGetValue(key, out var handler) || handler.SemanticOp == SemanticOp.Unknown) {
                // Fail-closed: never emit partial/guessed IL when a handler is Unknown!
                diagnostics.Add($"Method {site.Caller.FullName}: unknown/unverified handler key 0x{key:X8} at vIP {i}.");
                return false;
            }

            int operand = 0;
            if (HasInt32Operand(handler.SemanticOp)) {
                if (ms.Length - ms.Position < 4) {
                    diagnostics.Add($"Method {site.Caller.FullName}: truncated bytecode stream reading operand for {handler.SemanticOp} at vIP {i}.");
                    return false;
                }
                operand = br.ReadInt32();
            }
            vOps.Add((handler.SemanticOp, operand));
        }

        var ehSpecs = new List<(int Kind, int TryStart, int TryEnd, int HandlerStart, int HandlerEnd, int CatchTypeToken)>(ehCount);
        for (int i = 0; i < ehCount; i++) {
            if (ms.Length - ms.Position < 24) {
                diagnostics.Add($"Method {site.Caller.FullName}: truncated bytecode stream reading EH entry {i}.");
                return false;
            }
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
                else if (prev.Op == SemanticOp.LdArg) {
                    if (!site.Caller.IsStatic && prev.Operand == 0 && site.Caller.DeclaringType is not null) {
                        localTypes[vOps[i].Operand] = site.Caller.DeclaringType.ToTypeSignature();
                    }
                    else {
                        int paramIdx = site.Caller.IsStatic ? prev.Operand : prev.Operand - 1;
                        if (paramIdx >= 0 && paramIdx < site.Caller.Parameters.Count)
                            localTypes[vOps[i].Operand] = site.Caller.Parameters[paramIdx].ParameterType;
                    }
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
                    if (!site.Caller.IsStatic) {
                        if (operand == 0) {
                            newBody.Instructions.Add(CilOpCodes.Ldarg_0);
                        }
                        else if (operand > 0 && operand - 1 < site.Caller.Parameters.Count) {
                            newBody.Instructions.Add(CilOpCodes.Ldarg, site.Caller.Parameters[operand - 1]);
                        }
                        else {
                            diagnostics.Add($"Method {site.Caller.FullName}: instance LdArg index {operand} out of range at vIP {i}.");
                            return false;
                        }
                    }
                    else {
                        if (operand < 0 || operand >= site.Caller.Parameters.Count) {
                            diagnostics.Add($"Method {site.Caller.FullName}: static LdArg index {operand} out of range at vIP {i}.");
                            return false;
                        }
                        newBody.Instructions.Add(CilOpCodes.Ldarg, site.Caller.Parameters[operand]);
                    }
                    break;
                case SemanticOp.LdLoc:
                    if (operand < 0 || operand >= newBody.LocalVariables.Count) {
                        diagnostics.Add($"Method {site.Caller.FullName}: LdLoc index {operand} out of range at vIP {i}.");
                        return false;
                    }
                    newBody.Instructions.Add(CilOpCodes.Ldloc, newBody.LocalVariables[operand]);
                    break;
                case SemanticOp.StLoc:
                    if (operand < 0 || operand >= newBody.LocalVariables.Count) {
                        diagnostics.Add($"Method {site.Caller.FullName}: StLoc index {operand} out of range at vIP {i}.");
                        return false;
                    }
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
                    if (TryLookupMember(module, operand) is not IMethodDescriptor newObjCtor) {
                        diagnostics.Add($"Method {site.Caller.FullName}: invalid NewObj token 0x{operand:X8} at vIP {i}.");
                        return false;
                    }
                    newBody.Instructions.Add(CilOpCodes.Newobj, newObjCtor);
                    break;
                case SemanticOp.LdFld:
                    if (TryLookupMember(module, operand) is not IFieldDescriptor ldFld) {
                        diagnostics.Add($"Method {site.Caller.FullName}: invalid LdFld token 0x{operand:X8} at vIP {i}.");
                        return false;
                    }
                    newBody.Instructions.Add(CilOpCodes.Ldfld, ldFld);
                    break;
                case SemanticOp.StFld:
                    if (TryLookupMember(module, operand) is not IFieldDescriptor stFld) {
                        diagnostics.Add($"Method {site.Caller.FullName}: invalid StFld token 0x{operand:X8} at vIP {i}.");
                        return false;
                    }
                    newBody.Instructions.Add(CilOpCodes.Stfld, stFld);
                    break;
                case SemanticOp.Call:
                    if (TryLookupMember(module, operand) is not IMethodDescriptor callTarget) {
                        diagnostics.Add($"Method {site.Caller.FullName}: invalid Call token 0x{operand:X8} at vIP {i}.");
                        return false;
                    }
                    newBody.Instructions.Add(CilOpCodes.Call, callTarget);
                    break;
                case SemanticOp.CallVirt:
                    if (TryLookupMember(module, operand) is not IMethodDescriptor callVirtTarget) {
                        diagnostics.Add($"Method {site.Caller.FullName}: invalid CallVirt token 0x{operand:X8} at vIP {i}.");
                        return false;
                    }
                    newBody.Instructions.Add(CilOpCodes.Callvirt, callVirtTarget);
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
            if (eh.TryStart < 0 || eh.TryStart >= vOps.Count ||
                eh.TryEnd <= eh.TryStart || eh.TryEnd > vOps.Count ||
                eh.HandlerStart < 0 || eh.HandlerStart >= vOps.Count ||
                eh.HandlerEnd <= eh.HandlerStart || eh.HandlerEnd > vOps.Count) {
                diagnostics.Add($"Method {site.Caller.FullName}: EH region out of range (try [{eh.TryStart}..{eh.TryEnd}), handler [{eh.HandlerStart}..{eh.HandlerEnd})).");
                return false;
            }

            var cilEh = new CilExceptionHandler {
                HandlerType = eh.Kind == 0 ? CilExceptionHandlerType.Exception : CilExceptionHandlerType.Finally,
                TryStart = vIndexToCil[eh.TryStart].CreateLabel(),
                TryEnd = eh.TryEnd < vOps.Count
                    ? vIndexToCil[eh.TryEnd].CreateLabel()
                    : newBody.Instructions.EndLabel,
                HandlerStart = vIndexToCil[eh.HandlerStart].CreateLabel(),
                HandlerEnd = eh.HandlerEnd < vOps.Count
                    ? vIndexToCil[eh.HandlerEnd].CreateLabel()
                    : newBody.Instructions.EndLabel
            };
            if (eh.Kind == 0 && eh.CatchTypeToken != 0) {
                if (TryLookupMember(module, eh.CatchTypeToken) is not ITypeDefOrRef catchType) {
                    diagnostics.Add($"Method {site.Caller.FullName}: invalid EH catch type token 0x{eh.CatchTypeToken:X8}.");
                    return false;
                }
                cilEh.ExceptionType = catchType;
            }
            newBody.ExceptionHandlers.Add(cilEh);
        }

        newBody.Instructions.OptimizeMacros();
        newBody.Instructions.CalculateOffsets();
        site.Caller.CilMethodBody = newBody;
        newBody.ComputeMaxStack();
        return true;
    }

    private static int ResolveLabelIndex(CilInstructionCollection insns, ICilLabel label) {
        if (label is CilInstructionLabel il && il.Instruction is not null)
            return insns.IndexOf(il.Instruction);
        int offset = label.Offset;
        for (int i = 0; i < insns.Count; i++) {
            if (insns[i].Offset == offset)
                return i;
        }
        return -1;
    }

    private static IMetadataMember? TryLookupMember(ModuleDefinition module, int token) =>
        module.TryLookupMember(new MetadataToken((uint)token), out var member) ? member : null;

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
