using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using de4vmp.V2.Analysis;
using de4vmp.V2.Emulation;
using de4vmp.V2.Models;

namespace de4vmp.V2.Semantics;

/// <summary>
/// Syntax-invariant semantic handler classifier.
/// Combines CFF unflattening + bounded behavioral I/O probing (for polymorphic arithmetic/bitwise/comparison ops)
/// + unflattened structural semantic analysis (for stack/control-flow/managed-object ops).
/// Strictly fail-closed: returns SemanticOp.Unknown if classification is ambiguous.
/// </summary>
public sealed class HandlerSemanticClassifier {
    private readonly CffUnflattener _unflattener;
    private readonly BoundedCilEmulator _emulator;

    private static readonly (int A, int B)[] BinaryProbes = [
        (17, 5),
        (-13, 4),
        (0, 7),
        (255, 3),
        (42, 42),
        (7, 19)
    ];

    private static readonly int[] UnaryProbes = [0, 1, -1, 42, -999, 12345];

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

        // Step 3: Semantic classification of unflattened CIL instructions (managed ops, control flow, VM state)
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

        // Only probe pure arithmetic/comparison helper handlers that take (int, int) -> int or (int) -> int
        // or VM handlers whose core binary op is factored/directly evaluable via stack simulation.
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

        // Collect all called helper methods, accessed fields, and core semantic opcodes
        var calledNames = new HashSet<string>(StringComparer.Ordinal);
        var fieldNames = new HashSet<string>(StringComparer.Ordinal);
        var codes = new HashSet<CilCode>();

        foreach (var ins in insns) {
            codes.Add(ins.OpCode.Code);
            if (ins.Operand is IMethodDescriptor md && md.Name is not null)
                calledNames.Add(md.Name.Value);
            if (ins.Operand is IFieldDescriptor fd && fd.Name is not null)
                fieldNames.Add(fd.Name.Value);
        }

        // Check if handler delegates its core binary/unary op to a pure helper method on the VM type
        foreach (var ins in insns) {
            if (ins.OpCode.Code is CilCode.Call or CilCode.Callvirt &&
                ins.Operand is MethodDefinition callee &&
                callee.DeclaringType == handler.DeclaringType &&
                callee != handler &&
                callee.CilMethodBody is not null) {
                _unflattener.Unflatten(callee.CilMethodBody);
                if (TryClassifyByBehavioralProbing(callee, out var subOp, out var subEv))
                    return (subOp, $"{subEv} (via helper {callee.Name})");
            }
        }

        // Managed / reflection / VM-state semantic recognition
        if (calledNames.Contains("Op_Nop") || (insns.Count <= 2 && codes.Contains(CilCode.Ret) && fieldNames.Count == 0 && calledNames.Count == 0))
            return (SemanticOp.Nop, "Empty/nop handler body");

        if (calledNames.Contains("ReadI4") && calledNames.Contains("Push") && !calledNames.Contains("Pop") && !fieldNames.Contains("Ip") && !calledNames.Contains("GetArg") && !calledNames.Contains("GetLoc") && !calledNames.Contains("InvokeMember"))
            return (SemanticOp.LdcI4, "Reads int32 operand and pushes constant");

        if (calledNames.Contains("GetArg") && calledNames.Contains("Push"))
            return (SemanticOp.LdArg, "Loads VM argument slot and pushes");

        if (calledNames.Contains("GetLoc") && calledNames.Contains("Push"))
            return (SemanticOp.LdLoc, "Loads VM local slot and pushes");

        if (calledNames.Contains("SetLoc") && calledNames.Contains("Pop"))
            return (SemanticOp.StLoc, "Pops value and stores VM local slot");

        if (calledNames.Contains("Jump"))
            return (SemanticOp.Br, "Unconditional VM IP jump");

        if (calledNames.Contains("JumpIfTrue"))
            return (SemanticOp.BrTrue, "Conditional VM IP jump (true)");

        if (calledNames.Contains("JumpIfFalse"))
            return (SemanticOp.BrFalse, "Conditional VM IP jump (false)");

        if (calledNames.Contains("Halt"))
            return (SemanticOp.Ret, "Halts VM execution and sets return value");

        if (calledNames.Contains("VmNewObj"))
            return (SemanticOp.NewObj, "Allocates managed object via metadata token");

        if (calledNames.Contains("VmLdFld"))
            return (SemanticOp.LdFld, "Loads instance field via metadata token");

        if (calledNames.Contains("VmStFld"))
            return (SemanticOp.StFld, "Stores instance field via metadata token");

        if (calledNames.Contains("VmCallVirt"))
            return (SemanticOp.CallVirt, "Invokes virtual method via metadata token");

        if (calledNames.Contains("VmCall"))
            return (SemanticOp.Call, "Invokes method via metadata token");

        if (calledNames.Contains("VmLdElemI4"))
            return (SemanticOp.LdElemI4, "Loads int32 array element");

        if (calledNames.Contains("VmStElemI4"))
            return (SemanticOp.StElemI4, "Stores int32 array element");

        if (calledNames.Contains("VmLdLen"))
            return (SemanticOp.LdLen, "Loads array length");

        if (calledNames.Contains("VmLeave"))
            return (SemanticOp.Leave, "Exits protected EH region");

        if (calledNames.Contains("VmEndFinally"))
            return (SemanticOp.EndFinally, "Ends finally handler");

        // Direct inline arithmetic/comparison check when VM stack Push/Pop wraps a single CIL operator
        if (calledNames.Contains("Pop") && calledNames.Contains("Push")) {
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

            if (directOps.Count == 1)
                return (directOps[0], $"Single semantic CIL op ({directOps[0]}) between Pop/Push");
        }

        // Fail-closed: never guess!
        return (SemanticOp.Unknown, "Fail-closed: handler semantics could not be uniquely verified");
    }
}
