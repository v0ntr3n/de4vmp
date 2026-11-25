using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using de4vmp.V2.Analysis;
using de4vmp.V2.Emulation;
using de4vmp.V2.Models;

namespace de4vmp.V2.Semantics;

/// <summary>
/// Syntax-invariant, name-invariant semantic handler classifier.
/// Combines CFF unflattening + bounded behavioral I/O probing (for polymorphic arithmetic/bitwise/comparison ops)
/// + unflattened structural semantic analysis (for stack/control-flow/managed-object ops using VM field roles
/// and BCL/CIL semantics, with zero reliance on helper or field names).
/// Strictly fail-closed: returns SemanticOp.Unknown if classification is ambiguous or unverified.
/// </summary>
public sealed class HandlerSemanticClassifier {
    private readonly CffUnflattener _unflattener;
    private readonly BoundedCilEmulator _emulator;
    private readonly Dictionary<TypeDefinition, VmStructuralProfile> _profileCache = new();

    private static readonly (int A, int B)[] BinaryProbes = [
        (17, 5),
        (-13, 4),
        (0, 7),
        (255, 3),
        (42, 42),
        (7, 19)
    ];

    private static readonly int[] UnaryProbes = [0, 1, -1, 42, -999, 12345];

    private sealed record VmStructuralProfile(
        MethodDefinition? ReadI4Helper,
        MethodDefinition? PushHelper,
        MethodDefinition? PopHelper,
        MethodDefinition? GetArgHelper,
        MethodDefinition? GetLocHelper,
        MethodDefinition? SetLocHelper,
        IFieldDescriptor? IpField,
        IFieldDescriptor? SpField,
        IFieldDescriptor? StackField,
        IFieldDescriptor? LocalsField);

    public HandlerSemanticClassifier(CffUnflattener? unflattener = null, BoundedCilEmulator? emulator = null) {
        _unflattener = unflattener ?? new CffUnflattener();
        _emulator = emulator ?? new BoundedCilEmulator(maxSteps: 50_000, maxCallDepth: 4);
    }

    public ResolvedHandler Classify(uint opcodeKey, MethodDefinition handlerMethod, out int switchesEliminated) {
        switchesEliminated = 0;
        if (handlerMethod.CilMethodBody is not { } body) {
            return new ResolvedHandler(opcodeKey, handlerMethod, SemanticOp.Unknown, "No CIL body", 0, 0);
        }

        // Step 1: Unflatten CFF and eliminate algebraic opaque predicates
        var cff = _unflattener.Unflatten(body);
        switchesEliminated = cff.SwitchesEliminated;

        // Step 2: Check pure behavioral I/O equivalence on binary/unary arithmetic/comparison handlers
        // (Handles polymorphic / mutated handlers such as `a - (-b)` for Add, `(a | b) - (a & b)` for Xor, etc.)
        if (TryClassifyByBehavioralProbing(handlerMethod, out var probedOp, out string probeEvidence)) {
            return new ResolvedHandler(
                opcodeKey,
                handlerMethod,
                probedOp,
                probeEvidence,
                cff.OriginalInstructionCount,
                cff.FinalInstructionCount);
        }

        // Step 3: Name-invariant structural semantic classification of unflattened CIL instructions
        var (op, evidence) = ClassifyUnflattenedStructure(handlerMethod);
        return new ResolvedHandler(
            opcodeKey,
            handlerMethod,
            op,
            evidence,
            cff.OriginalInstructionCount,
            cff.FinalInstructionCount);
    }

    private bool TryClassifyByBehavioralProbing(
        MethodDefinition handler,
        out SemanticOp op,
        out string evidence) {
        op = SemanticOp.Unknown;
        evidence = string.Empty;

        if (handler.Parameters.Count == 2 &&
            handler.Parameters[0].ParameterType.FullName == "System.Int32" &&
            handler.Parameters[1].ParameterType.FullName == "System.Int32" &&
            handler.Signature?.ReturnType.FullName == "System.Int32") {
            var candidates = new (SemanticOp Op, Func<int, int, int> Expected)[] {
                (SemanticOp.Add, (a, b) => unchecked(a + b)),
                (SemanticOp.Sub, (a, b) => unchecked(a - b)),
                (SemanticOp.Mul, (a, b) => unchecked(a * b)),
                (SemanticOp.Div, (a, b) => a / b),
                (SemanticOp.Rem, (a, b) => a % b),
                (SemanticOp.Xor, (a, b) => a ^ b),
                (SemanticOp.And, (a, b) => a & b),
                (SemanticOp.Or,  (a, b) => a | b),
                (SemanticOp.Shl, (a, b) => a << (b & 31)),
                (SemanticOp.Shr, (a, b) => a >> (b & 31)),
                (SemanticOp.Ceq, (a, b) => a == b ? 1 : 0),
                (SemanticOp.Clt, (a, b) => a < b ? 1 : 0),
                (SemanticOp.Cgt, (a, b) => a > b ? 1 : 0),
            };

            var results = new int[BinaryProbes.Length];
            for (int i = 0; i < BinaryProbes.Length; i++) {
                var snap = _emulator.EmulateMethod(handler, [BinaryProbes[i].A, BinaryProbes[i].B]);
                if (!snap.CompletedNormally || snap.ReturnValue is not int val)
                    return false;
                results[i] = val;
            }

            var matched = candidates
                .Where(c => Enumerable.Range(0, BinaryProbes.Length)
                    .All(i => c.Expected(BinaryProbes[i].A, BinaryProbes[i].B) == results[i]))
                .Select(c => c.Op)
                .ToList();

            if (matched.Count == 1) {
                op = matched[0];
                evidence = $"Verified via behavioral I/O equivalence across {BinaryProbes.Length} probes";
                return true;
            }
        }

        if (handler.Parameters.Count == 1 &&
            handler.Parameters[0].ParameterType.FullName == "System.Int32" &&
            handler.Signature?.ReturnType.FullName == "System.Int32") {
            var results = new int[UnaryProbes.Length];
            for (int i = 0; i < UnaryProbes.Length; i++) {
                var snap = _emulator.EmulateMethod(handler, [UnaryProbes[i]]);
                if (!snap.CompletedNormally || snap.ReturnValue is not int val)
                    return false;
                results[i] = val;
            }

            if (Enumerable.Range(0, UnaryProbes.Length).All(i => unchecked(-UnaryProbes[i]) == results[i])) {
                op = SemanticOp.Neg;
                evidence = $"Verified via unary behavioral I/O equivalence across {UnaryProbes.Length} probes";
                return true;
            }
        }

        return false;
    }

    private (SemanticOp Op, string Evidence) ClassifyUnflattenedStructure(MethodDefinition handler) {
        var insns = handler.CilMethodBody!.Instructions;
        var vmType = handler.DeclaringType;

        // Check if handler delegates its core binary/unary op to a pure helper method on the VM type
        foreach (var ins in insns) {
            if (ins.OpCode.Code is CilCode.Call or CilCode.Callvirt &&
                ins.Operand is MethodDefinition callee &&
                callee.DeclaringType == vmType &&
                callee != handler &&
                callee.CilMethodBody is not null) {
                _unflattener.Unflatten(callee.CilMethodBody);
                if (TryClassifyByBehavioralProbing(callee, out var subOp, out var subEv))
                    return (subOp, $"{subEv} (via helper {callee.Name})");
            }
        }

        var profile = vmType is not null ? GetOrAnalyzeProfile(vmType) : null;

        // If handler is a thin wrapper calling a single void() helper method on the VM type, inspect that helper's body.
        var effectiveInsns = ResolveEffectiveInstructions(handler, vmType);

        var calledVmMethods = new HashSet<MethodDefinition>();
        var bclCalls = new HashSet<(string DeclType, string Name)>();
        var codes = new HashSet<CilCode>();
        var storedFields = new HashSet<IFieldDescriptor>();
        var loadedFields = new HashSet<IFieldDescriptor>();

        foreach (var ins in effectiveInsns) {
            codes.Add(ins.OpCode.Code);
            if (ins.OpCode.Code is CilCode.Call or CilCode.Callvirt && ins.Operand is IMethodDescriptor md) {
                if (md is MethodDefinition localDef && localDef.DeclaringType == vmType) {
                    calledVmMethods.Add(localDef);
                }
                else {
                    string declName = md.DeclaringType?.FullName ?? string.Empty;
                    string methodName = md.Name ?? string.Empty;
                    bclCalls.Add((declName, methodName));
                }
            }
            else if (ins.OpCode.Code is CilCode.Stfld or CilCode.Stsfld && ins.Operand is IFieldDescriptor sfd) {
                storedFields.Add(sfd);
            }
            else if (ins.OpCode.Code is CilCode.Ldfld or CilCode.Ldsfld && ins.Operand is IFieldDescriptor lfd) {
                loadedFields.Add(lfd);
            }
        }

        var matches = new List<(SemanticOp Op, string Evidence)>();

        // 1. Nop: pure empty body (only Nop/Ret, zero side effects)
        if (effectiveInsns.All(i => i.OpCode.Code is CilCode.Nop or CilCode.Ret) &&
            codes.Contains(CilCode.Ret) &&
            calledVmMethods.Count == 0 && bclCalls.Count == 0 && storedFields.Count == 0 && loadedFields.Count == 0) {
            matches.Add((SemanticOp.Nop, "Empty/nop handler body"));
        }

        // 2. Stack / operand / argument / local transfers (identified via structural helper roles)
        if (profile is not null && bclCalls.Count == 0 && storedFields.Count == 0) {
            if (profile.ReadI4Helper is not null && profile.PushHelper is not null &&
                calledVmMethods.Count == 2 &&
                calledVmMethods.Contains(profile.ReadI4Helper) &&
                calledVmMethods.Contains(profile.PushHelper)) {
                matches.Add((SemanticOp.LdcI4, "Reads int32 operand and pushes constant"));
            }

            if (profile.GetArgHelper is not null && profile.PushHelper is not null &&
                calledVmMethods.Count == 2 &&
                calledVmMethods.Contains(profile.GetArgHelper) &&
                calledVmMethods.Contains(profile.PushHelper)) {
                matches.Add((SemanticOp.LdArg, "Loads VM argument slot and pushes"));
            }

            if (profile.GetLocHelper is not null && profile.PushHelper is not null &&
                calledVmMethods.Count == 2 &&
                calledVmMethods.Contains(profile.GetLocHelper) &&
                calledVmMethods.Contains(profile.PushHelper)) {
                matches.Add((SemanticOp.LdLoc, "Loads VM local slot and pushes"));
            }

            if (profile.PopHelper is not null && profile.SetLocHelper is not null &&
                calledVmMethods.Count == 2 &&
                calledVmMethods.Contains(profile.PopHelper) &&
                calledVmMethods.Contains(profile.SetLocHelper)) {
                matches.Add((SemanticOp.StLoc, "Pops value and stores VM local slot"));
            }
        }

        // 3. Control-flow & EH handlers (identified via IP/SP/EH-stack mutations)
        bool hasBrFalse = codes.Contains(CilCode.Brfalse) || codes.Contains(CilCode.Brfalse_S);
        bool hasBrTrue = codes.Contains(CilCode.Brtrue) || codes.Contains(CilCode.Brtrue_S);
        bool hasAnyCondBranch = hasBrFalse || hasBrTrue ||
            codes.Contains(CilCode.Beq) || codes.Contains(CilCode.Beq_S) ||
            codes.Contains(CilCode.Bne_Un) || codes.Contains(CilCode.Bne_Un_S) ||
            codes.Contains(CilCode.Blt) || codes.Contains(CilCode.Blt_S) ||
            codes.Contains(CilCode.Bgt) || codes.Contains(CilCode.Bgt_S) ||
            codes.Contains(CilCode.Ble) || codes.Contains(CilCode.Ble_S) ||
            codes.Contains(CilCode.Bge) || codes.Contains(CilCode.Bge_S);

        if (profile?.IpField is not null && storedFields.Contains(profile.IpField)) {
            bool readsIpOperand = profile.ReadI4Helper is not null && calledVmMethods.Contains(profile.ReadI4Helper);
            bool popsCondition = profile.PopHelper is not null && calledVmMethods.Contains(profile.PopHelper);
            bool writesSp = profile.SpField is not null && storedFields.Contains(profile.SpField);

            if (readsIpOperand && !popsCondition && !hasAnyCondBranch && !writesSp && bclCalls.Count == 0) {
                matches.Add((SemanticOp.Br, "Unconditional VM IP jump"));
            }

            if (readsIpOperand && popsCondition && hasBrFalse && !hasBrTrue && !writesSp && bclCalls.Count == 0) {
                matches.Add((SemanticOp.BrTrue, "Conditional VM IP jump (true)"));
            }

            if (readsIpOperand && popsCondition && hasBrTrue && !hasBrFalse && !writesSp && bclCalls.Count == 0) {
                matches.Add((SemanticOp.BrFalse, "Conditional VM IP jump (false)"));
            }

            if (readsIpOperand && writesSp && !hasAnyCondBranch && bclCalls.Count == 0) {
                matches.Add((SemanticOp.Leave, "Exits protected EH region (resets SP and jumps IP)"));
            }

            if (bclCalls.Any(c => c.DeclType.StartsWith("System.Collections.Generic.Stack`1", StringComparison.Ordinal) && c.Name == "Pop") &&
                !readsIpOperand && !hasAnyCondBranch) {
                matches.Add((SemanticOp.EndFinally, "Ends finally handler (restores IP from EH stack)"));
            }
        }

        // 4. Ret / Halt: stores true (1) into a System.Boolean VM state field with no calls
        if (storedFields.Count == 1 && calledVmMethods.Count == 0 && bclCalls.Count == 0 && !hasAnyCondBranch) {
            var onlyField = storedFields.First();
            if (onlyField.Signature?.FieldType.FullName == "System.Boolean" &&
                StoresConstantOneToField(effectiveInsns, onlyField)) {
                matches.Add((SemanticOp.Ret, "Halts VM execution via boolean halt flag"));
            }
        }

        // 5. Managed object & reflection operations (BCL API semantics)
        if (bclCalls.Contains(("System.Activator", "CreateInstance")) ||
            bclCalls.Contains(("System.Reflection.ConstructorInfo", "Invoke"))) {
            matches.Add((SemanticOp.NewObj, "Allocates managed object via reflection/Activator"));
        }

        if (bclCalls.Contains(("System.Reflection.FieldInfo", "GetValue"))) {
            matches.Add((SemanticOp.LdFld, "Loads instance field via FieldInfo.GetValue"));
        }

        if (bclCalls.Contains(("System.Reflection.FieldInfo", "SetValue"))) {
            matches.Add((SemanticOp.StFld, "Stores instance field via FieldInfo.SetValue"));
        }

        if (bclCalls.Contains(("System.Reflection.MethodBase", "Invoke"))) {
            bool isVirtualDispatch =
                bclCalls.Contains(("System.Reflection.MethodBase", "get_IsVirtual")) ||
                bclCalls.Contains(("System.Object", "GetType"));
            if (isVirtualDispatch) {
                matches.Add((SemanticOp.CallVirt, "Invokes virtual method via MethodBase.Invoke + virtual dispatch check"));
            }
            else {
                matches.Add((SemanticOp.Call, "Invokes method via MethodBase.Invoke"));
            }
        }

        // 6. Managed array operations (real CIL array opcodes, excluding VM internal stack/locals access)
        bool touchesVmInternalArray = profile is not null &&
            ((profile.StackField is not null && loadedFields.Contains(profile.StackField)) ||
             (profile.LocalsField is not null && loadedFields.Contains(profile.LocalsField)));

        if (bclCalls.Count == 0 && !touchesVmInternalArray) {
            if (codes.Contains(CilCode.Ldelem_I4) && !codes.Contains(CilCode.Stelem_I4) && !codes.Contains(CilCode.Ldlen)) {
                matches.Add((SemanticOp.LdElemI4, "Loads int32 array element (ldelem.i4)"));
            }
            if (codes.Contains(CilCode.Stelem_I4) && !codes.Contains(CilCode.Ldelem_I4) && !codes.Contains(CilCode.Ldlen)) {
                matches.Add((SemanticOp.StElemI4, "Stores int32 array element (stelem.i4)"));
            }
            if (codes.Contains(CilCode.Ldlen) && !codes.Contains(CilCode.Ldelem_I4) && !codes.Contains(CilCode.Stelem_I4)) {
                matches.Add((SemanticOp.LdLen, "Loads array length (ldlen)"));
            }
        }

        if (matches.Count == 1)
            return matches[0];

        if (matches.Count > 1)
            return (SemanticOp.Unknown, $"Fail-closed: ambiguous structural classification ({string.Join(", ", matches.Select(m => m.Op))})");

        // 7. Strict inline single-op arithmetic/comparison fallback:
        // ONLY when the handler directly wraps a single arithmetic/comparison CIL opcode between structurally-identified
        // Pop and Push helpers, with no other calls, no direct field accesses, no branches, and no array/object ops.
        if (profile?.PopHelper is not null && profile.PushHelper is not null &&
            calledVmMethods.Count == 2 &&
            calledVmMethods.Contains(profile.PopHelper) &&
            calledVmMethods.Contains(profile.PushHelper) &&
            bclCalls.Count == 0 && storedFields.Count == 0 && loadedFields.Count == 0 &&
            !hasAnyCondBranch &&
            !codes.Contains(CilCode.Ldelem_I4) && !codes.Contains(CilCode.Stelem_I4) && !codes.Contains(CilCode.Ldlen)) {
            var directOps = new List<SemanticOp>();
            if (codes.Contains(CilCode.Add)) directOps.Add(SemanticOp.Add);
            if (codes.Contains(CilCode.Sub)) directOps.Add(SemanticOp.Sub);
            if (codes.Contains(CilCode.Mul)) directOps.Add(SemanticOp.Mul);
            if (codes.Contains(CilCode.Div)) directOps.Add(SemanticOp.Div);
            if (codes.Contains(CilCode.Rem)) directOps.Add(SemanticOp.Rem);
            if (codes.Contains(CilCode.Xor)) directOps.Add(SemanticOp.Xor);
            if (codes.Contains(CilCode.And)) directOps.Add(SemanticOp.And);
            if (codes.Contains(CilCode.Or)) directOps.Add(SemanticOp.Or);
            if (codes.Contains(CilCode.Shl)) directOps.Add(SemanticOp.Shl);
            if (codes.Contains(CilCode.Shr)) directOps.Add(SemanticOp.Shr);
            if (codes.Contains(CilCode.Neg)) directOps.Add(SemanticOp.Neg);
            if (codes.Contains(CilCode.Ceq)) directOps.Add(SemanticOp.Ceq);
            if (codes.Contains(CilCode.Clt)) directOps.Add(SemanticOp.Clt);
            if (codes.Contains(CilCode.Cgt)) directOps.Add(SemanticOp.Cgt);

            if (directOps.Count == 1 && !insns.Any(i => i.IsLdcI4())) {
                int popCalls = insns.Count(i => i.OpCode.Code is CilCode.Call or CilCode.Callvirt && ReferenceEquals(i.Operand, profile.PopHelper));
                int expectedPops = directOps[0] == SemanticOp.Neg ? 1 : 2;
                if (popCalls == expectedPops)
                    return (directOps[0], $"Single semantic CIL op ({directOps[0]}) between structural Pop/Push");
            }
        }

        // Fail-closed: never guess!
        return (SemanticOp.Unknown, "Fail-closed: handler semantics could not be uniquely verified");
    }

    private static IList<CilInstruction> ResolveEffectiveInstructions(MethodDefinition handler, TypeDefinition? vmType) {
        var insns = handler.CilMethodBody!.Instructions;
        if (vmType is null)
            return insns;

        MethodDefinition? singleVoidHelper = null;
        foreach (var ins in insns) {
            var code = ins.OpCode.Code;
            if (code is CilCode.Ldfld or CilCode.Stfld or CilCode.Ldsfld or CilCode.Stsfld
                or CilCode.Ldelem_I4 or CilCode.Stelem_I4 or CilCode.Ldlen) {
                return insns;
            }
            if (code is CilCode.Call or CilCode.Callvirt) {
                if (ins.Operand is MethodDefinition callee &&
                    callee.DeclaringType == vmType &&
                    callee != handler &&
                    callee.Parameters.Count == 0 &&
                    callee.Signature?.ReturnType.FullName == "System.Void" &&
                    callee.CilMethodBody is not null) {
                    if (singleVoidHelper is not null)
                        return insns;
                    singleVoidHelper = callee;
                    continue;
                }
                return insns;
            }
        }

        return singleVoidHelper?.CilMethodBody?.Instructions ?? insns;
    }

    private VmStructuralProfile GetOrAnalyzeProfile(TypeDefinition vmType) {
        if (_profileCache.TryGetValue(vmType, out var cached))
            return cached;

        var profile = AnalyzeVmType(vmType);
        _profileCache[vmType] = profile;
        return profile;
    }

    private static VmStructuralProfile AnalyzeVmType(TypeDefinition vmType) {
        var methods = vmType.Methods.Where(m => !m.IsStatic && !m.IsConstructor && m.CilMethodBody is not null).ToList();

        // 1. Identify ReadI4Helper & IpField: () -> int32 calling BitConverter.ToInt32 (or reading byte[]) and advancing an int32 field
        var readI4Candidates = new List<(MethodDefinition Method, IFieldDescriptor IpField)>();
        foreach (var m in methods) {
            if (m.Parameters.Count != 0 || m.Signature?.ReturnType.FullName != "System.Int32")
                continue;
            var insns = m.CilMethodBody!.Instructions;
            bool readsByteStream = insns.Any(i =>
                (i.OpCode.Code is CilCode.Call or CilCode.Callvirt &&
                 i.Operand is IMethodDescriptor md &&
                 md.DeclaringType?.FullName == "System.BitConverter" &&
                 md.Name == "ToInt32") ||
                (i.OpCode.Code == CilCode.Ldfld &&
                 i.Operand is IFieldDescriptor fd &&
                 fd.Signature?.FieldType.FullName == "System.Byte[]"));
            if (!readsByteStream)
                continue;

            var advancedIntField = FindIncrementedIntField(insns, isIncrement: true);
            if (advancedIntField is not null)
                readI4Candidates.Add((m, advancedIntField));
        }

        MethodDefinition? readI4Helper = readI4Candidates.Count == 1 ? readI4Candidates[0].Method : null;
        IFieldDescriptor? ipField = readI4Candidates.Count == 1 ? readI4Candidates[0].IpField : null;

        // 2. Identify PushHelper, StackField, SpField: (int32) -> void writing int32[] via stelem.i4 and incrementing an int32 field
        var pushCandidates = new List<(MethodDefinition Method, IFieldDescriptor StackField, IFieldDescriptor SpField)>();
        foreach (var m in methods) {
            if (m.Parameters.Count != 1 ||
                m.Parameters[0].ParameterType.FullName != "System.Int32" ||
                m.Signature?.ReturnType.FullName != "System.Void")
                continue;
            var insns = m.CilMethodBody!.Instructions;
            if (!insns.Any(i => i.OpCode.Code == CilCode.Stelem_I4))
                continue;

            var spCandidate = FindIncrementedIntField(insns, isIncrement: true);
            var stackCandidate = insns
                .Where(i => i.OpCode.Code == CilCode.Ldfld && i.Operand is IFieldDescriptor fd && fd.Signature?.FieldType.FullName == "System.Int32[]")
                .Select(i => (IFieldDescriptor)i.Operand!)
                .Distinct()
                .ToList();

            if (spCandidate is not null && stackCandidate.Count == 1)
                pushCandidates.Add((m, stackCandidate[0], spCandidate));
        }

        MethodDefinition? pushHelper = pushCandidates.Count == 1 ? pushCandidates[0].Method : null;
        IFieldDescriptor? stackField = pushCandidates.Count == 1 ? pushCandidates[0].StackField : null;
        IFieldDescriptor? spField = pushCandidates.Count == 1 ? pushCandidates[0].SpField : null;

        // 3. Identify PopHelper: () -> int32 decrementing SpField and reading StackField via ldelem.i4
        var popCandidates = new List<MethodDefinition>();
        if (spField is not null && stackField is not null) {
            foreach (var m in methods) {
                if (m.Parameters.Count != 0 || m.Signature?.ReturnType.FullName != "System.Int32")
                    continue;
                var insns = m.CilMethodBody!.Instructions;
                if (!insns.Any(i => i.OpCode.Code == CilCode.Ldelem_I4))
                    continue;
                var decField = FindIncrementedIntField(insns, isIncrement: false);
                bool readsStack = insns.Any(i => i.OpCode.Code == CilCode.Ldfld && ReferenceEquals(i.Operand, stackField));
                if (ReferenceEquals(decField, spField) && readsStack)
                    popCandidates.Add(m);
            }
        }
        MethodDefinition? popHelper = popCandidates.Count == 1 ? popCandidates[0] : null;

        // 4. Identify GetArgHelper: () -> int32 calling ReadI4Helper and reading an object[] field via ldelem.ref
        var getArgCandidates = new List<MethodDefinition>();
        if (readI4Helper is not null) {
            foreach (var m in methods) {
                if (m.Parameters.Count != 0 || m.Signature?.ReturnType.FullName != "System.Int32")
                    continue;
                var insns = m.CilMethodBody!.Instructions;
                bool callsReadI4 = insns.Any(i => i.OpCode.Code is CilCode.Call or CilCode.Callvirt && ReferenceEquals(i.Operand, readI4Helper));
                bool readsObjArr = insns.Any(i => i.OpCode.Code == CilCode.Ldelem_Ref) &&
                    insns.Any(i => i.OpCode.Code == CilCode.Ldfld && i.Operand is IFieldDescriptor fd && fd.Signature?.FieldType.FullName == "System.Object[]");
                if (callsReadI4 && readsObjArr)
                    getArgCandidates.Add(m);
            }
        }
        MethodDefinition? getArgHelper = getArgCandidates.Count == 1 ? getArgCandidates[0] : null;

        // 5. Identify GetLocHelper & LocalsField: () -> int32 calling ReadI4Helper and reading an int32[] field != StackField
        var getLocCandidates = new List<(MethodDefinition Method, IFieldDescriptor LocalsField)>();
        if (readI4Helper is not null) {
            foreach (var m in methods) {
                if (m.Parameters.Count != 0 || m.Signature?.ReturnType.FullName != "System.Int32")
                    continue;
                var insns = m.CilMethodBody!.Instructions;
                bool callsReadI4 = insns.Any(i => i.OpCode.Code is CilCode.Call or CilCode.Callvirt && ReferenceEquals(i.Operand, readI4Helper));
                if (!callsReadI4 || !insns.Any(i => i.OpCode.Code == CilCode.Ldelem_I4))
                    continue;

                var intArrFields = insns
                    .Where(i => i.OpCode.Code == CilCode.Ldfld &&
                                i.Operand is IFieldDescriptor fd &&
                                fd.Signature?.FieldType.FullName == "System.Int32[]" &&
                                !ReferenceEquals(fd, stackField))
                    .Select(i => (IFieldDescriptor)i.Operand!)
                    .Distinct()
                    .ToList();
                if (intArrFields.Count == 1)
                    getLocCandidates.Add((m, intArrFields[0]));
            }
        }
        MethodDefinition? getLocHelper = getLocCandidates.Count == 1 ? getLocCandidates[0].Method : null;
        IFieldDescriptor? localsField = getLocCandidates.Count == 1 ? getLocCandidates[0].LocalsField : null;

        // 6. Identify SetLocHelper: (int32) -> void calling ReadI4Helper and writing LocalsField via stelem.i4
        var setLocCandidates = new List<MethodDefinition>();
        if (readI4Helper is not null && localsField is not null) {
            foreach (var m in methods) {
                if (m.Parameters.Count != 1 ||
                    m.Parameters[0].ParameterType.FullName != "System.Int32" ||
                    m.Signature?.ReturnType.FullName != "System.Void")
                    continue;
                var insns = m.CilMethodBody!.Instructions;
                bool callsReadI4 = insns.Any(i => i.OpCode.Code is CilCode.Call or CilCode.Callvirt && ReferenceEquals(i.Operand, readI4Helper));
                bool writesLocals = insns.Any(i => i.OpCode.Code == CilCode.Stelem_I4) &&
                    insns.Any(i => i.OpCode.Code == CilCode.Ldfld && ReferenceEquals(i.Operand, localsField));
                if (callsReadI4 && writesLocals)
                    setLocCandidates.Add(m);
            }
        }
        MethodDefinition? setLocHelper = setLocCandidates.Count == 1 ? setLocCandidates[0] : null;

        return new VmStructuralProfile(
            readI4Helper,
            pushHelper,
            popHelper,
            getArgHelper,
            getLocHelper,
            setLocHelper,
            ipField,
            spField,
            stackField,
            localsField);
    }

    private static IFieldDescriptor? FindIncrementedIntField(CilInstructionCollection insns, bool isIncrement) {
        var targetOp = isIncrement ? CilCode.Add : CilCode.Sub;
        IFieldDescriptor? found = null;
        for (int i = 0; i + 3 < insns.Count; i++) {
            if (insns[i].OpCode.Code == CilCode.Ldfld &&
                insns[i].Operand is IFieldDescriptor fd &&
                fd.Signature?.FieldType.FullName == "System.Int32" &&
                insns[i + 1].IsLdcI4() &&
                insns[i + 2].OpCode.Code == targetOp &&
                insns[i + 3].OpCode.Code == CilCode.Stfld &&
                ReferenceEquals(insns[i + 3].Operand, fd)) {
                if (found is not null && !ReferenceEquals(found, fd))
                    return null;
                found = fd;
            }
        }
        return found;
    }

    private static bool StoresConstantOneToField(IList<CilInstruction> insns, IFieldDescriptor field) {
        for (int i = 1; i < insns.Count; i++) {
            if (insns[i].OpCode.Code is CilCode.Stfld or CilCode.Stsfld &&
                ReferenceEquals(insns[i].Operand, field) &&
                insns[i - 1].IsLdcI4() &&
                insns[i - 1].GetLdcI4Constant() == 1) {
                return true;
            }
        }
        return false;
    }
}
