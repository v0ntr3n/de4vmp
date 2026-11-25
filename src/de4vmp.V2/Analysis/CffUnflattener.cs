using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace de4vmp.V2.Analysis;

public sealed record CffUnflattenResult(
    bool WasFlattened,
    int SwitchesEliminated,
    int OriginalInstructionCount,
    int FinalInstructionCount);

/// <summary>
/// Control-flow graph (CFG) based switch-dispatcher unflattener and algebraic opaque-predicate simplifier for CIL.
/// Operates purely statically on AsmResolver CilMethodBody instructions.
/// </summary>
public sealed class CffUnflattener {
    public CffUnflattenResult Unflatten(CilMethodBody body) {
        var insns = body.Instructions;
        int originalCount = insns.Count;
        if (originalCount < 6)
            return new CffUnflattenResult(false, 0, originalCount, originalCount);

        insns.ExpandMacros();
        insns.CalculateOffsets();

        int switchesEliminated = 0;
        bool changed;
        int guard = 0;

        do {
            changed = false;
            guard++;
            if (guard > 16)
                break;

            // 1. Simplify known algebraic opaque predicates (e.g. (x * (x + 1)) % 2 == 0 or & 1 == 0)
            if (SimplifyOpaquePredicates(insns)) {
                changed = true;
            }

            // 2. Fold constant-expression switch dispatchers
            if (TryUnflattenOneDispatcher(insns, out bool switchEliminated)) {
                if (switchEliminated)
                    switchesEliminated++;
                changed = true;
            }

            if (changed) {
                RemoveUnreachableInstructions(insns, body);
                insns.CalculateOffsets();
            }
        } while (changed);

        insns.OptimizeMacros();
        insns.CalculateOffsets();

        return new CffUnflattenResult(
            switchesEliminated > 0 || insns.Count < originalCount,
            switchesEliminated,
            originalCount,
            insns.Count);
    }

    /// <summary>
    /// Detects and folds algebraic tautology: (x * (x + 1)) % 2 == 0 or ((x * (x + 1)) & 1) == 0.
    /// Since the product of two consecutive integers is always even, the expression is always 0.
    /// </summary>
    private static bool SimplifyOpaquePredicates(CilInstructionCollection insns) {
        bool modified = false;
        for (int i = 0; i + 7 < insns.Count; i++) {
            // Pattern: ldloc V; ldloc V; ldc.i4 1; add; mul; ldc.i4 (1|2); (and|rem|rem.un); (brfalse|brtrue) target
            if (insns[i].OpCode.Code != CilCode.Ldloc ||
                insns[i + 1].OpCode.Code != CilCode.Ldloc ||
                !Equals(insns[i].Operand, insns[i + 1].Operand))
                continue;

            if (!IsConstant(insns[i + 2], 1) ||
                insns[i + 3].OpCode.Code != CilCode.Add ||
                insns[i + 4].OpCode.Code != CilCode.Mul)
                continue;

            bool isMod2 = IsConstant(insns[i + 5], 2) &&
                          (insns[i + 6].OpCode.Code is CilCode.Rem or CilCode.Rem_Un);
            bool isAnd1 = IsConstant(insns[i + 5], 1) &&
                          insns[i + 6].OpCode.Code == CilCode.And;

            if (!isMod2 && !isAnd1)
                continue;

            // Never rewrite if any branch targets an interior instruction of the opaque predicate sequence.
            if (HasBranchTargetInRange(insns, i + 1, i + 7, -1))
                continue;

            var branch = insns[i + 7];
            if (branch.OpCode.Code == CilCode.Brfalse) {
                // Result is always 0 -> brfalse is ALWAYS taken
                for (int k = i; k < i + 7; k++) {
                    insns[k].OpCode = CilOpCodes.Nop;
                    insns[k].Operand = null;
                }
                branch.OpCode = CilOpCodes.Br;
                modified = true;
            }
            else if (branch.OpCode.Code == CilCode.Brtrue) {
                // Result is always 0 -> brtrue is NEVER taken
                for (int k = i; k <= i + 7; k++) {
                    insns[k].OpCode = CilOpCodes.Nop;
                    insns[k].Operand = null;
                }
                modified = true;
            }
        }
        return modified;
    }

    private static bool TryUnflattenOneDispatcher(CilInstructionCollection insns, out bool switchEliminated) {
        switchEliminated = false;
        // Locate a switch instruction fed by a state local:
        //   ldloc S [; ldc.i4 K; (xor|rem|rem.un|and)] ; switch (targets...)
        int switchIdx = -1;
        CilLocalVariable? stateVar = null;
        int dispatcherStart = -1;
        Func<int, int> indexTransform = x => x;

        for (int i = 1; i < insns.Count; i++) {
            if (insns[i].OpCode.Code != CilCode.Switch)
                continue;

            if (insns[i - 1].OpCode.Code == CilCode.Ldloc && insns[i - 1].Operand is CilLocalVariable v1) {
                switchIdx = i;
                stateVar = v1;
                dispatcherStart = i - 1;
                indexTransform = x => x;
                break;
            }

            if (i >= 3 &&
                insns[i - 3].OpCode.Code == CilCode.Ldloc && insns[i - 3].Operand is CilLocalVariable v2 &&
                insns[i - 2].IsLdcI4() &&
                insns[i - 1].OpCode.Code is CilCode.Xor or CilCode.Rem or CilCode.Rem_Un or CilCode.And) {
                int k = insns[i - 2].GetLdcI4Constant();
                var op = insns[i - 1].OpCode.Code;
                switchIdx = i;
                stateVar = v2;
                dispatcherStart = i - 3;
                indexTransform = op switch {
                    CilCode.Xor => x => x ^ k,
                    CilCode.Rem => x => (k != 0 && !(x == int.MinValue && k == -1)) ? x % k : -1,
                    CilCode.Rem_Un => x => k != 0 ? (int)((uint)x % (uint)k) : -1,
                    CilCode.And => x => x & k,
                    _ => x => x
                };
                break;
            }
        }

        if (switchIdx < 0 || stateVar is null || insns[switchIdx].Operand is not IList<ICilLabel> rawTargets || rawTargets.Count == 0)
            return false;

        var targetIndices = rawTargets.Select(t => ResolveTargetIndex(insns, t)).ToArray();
        if (targetIndices.Any(t => t < 0))
            return false;
        var targetInsns = targetIndices.Select(t => insns[t]).ToArray();

        // Find all assignments to stateVar that branch back to dispatcherStart (or fall through into dispatcherStart)
        int rewired = 0;

        // Pattern A: `ldc.i4 NEXT; stloc S; [pure straight-line setup;] (br dispatcherStart | fallthrough into dispatcherStart)`
        for (int i = 0; i < insns.Count; i++) {
            if (insns[i].OpCode.Code != CilCode.Stloc || !Equals(insns[i].Operand, stateVar))
                continue;

            // Scan forward from i + 1 across nops and optional straight-line instructions that do not touch stateVar
            int scan = i + 1;
            int nonNopIntervening = 0;
            bool goesToDispatcher = false;
            int jumpIdx = -1;

            while (scan < insns.Count && nonNopIntervening <= 8) {
                if (scan == dispatcherStart) {
                    goesToDispatcher = true;
                    break;
                }
                var cur = insns[scan];
                if (cur.OpCode.Code == CilCode.Nop) {
                    scan++;
                    continue;
                }
                if (cur.OpCode.Code == CilCode.Br &&
                    cur.Operand is ICilLabel lbl &&
                    ResolveTargetIndex(insns, lbl) == dispatcherStart) {
                    goesToDispatcher = true;
                    jumpIdx = scan;
                    break;
                }
                // Allow intervening straight-line instructions that do not read/write stateVar or branch
                if (cur.OpCode.FlowControl == CilFlowControl.Next &&
                    !(cur.OpCode.Code is CilCode.Ldloc or CilCode.Stloc or CilCode.Ldloca && Equals(cur.Operand, stateVar))) {
                    nonNopIntervening++;
                    scan++;
                    continue;
                }
                break;
            }

            if (!goesToDispatcher)
                continue;

            // Evaluate constant expression feeding `stloc stateVar`
            if (!TryEvalConstantBackward(insns, i - 1, out int nextState, out int exprStart))
                continue;

            // Guard against corrupting mid-sequence jump targets in [exprStart+1 .. scan-1] (and jumpIdx if present)
            int guardEnd = jumpIdx >= 0 ? jumpIdx : scan - 1;
            if (guardEnd >= exprStart + 1 && HasBranchTargetInRange(insns, exprStart + 1, guardEnd, -1))
                continue;

            int caseIndex = indexTransform(nextState);
            if (caseIndex < 0 || caseIndex >= targetInsns.Length)
                continue;

            var targetInsn = targetInsns[caseIndex];

            // Rewrite: nop out the constant expression feeding stateVar
            for (int k = exprStart; k < i; k++) {
                insns[k].OpCode = CilOpCodes.Nop;
                insns[k].Operand = null;
            }

            if (jumpIdx >= 0) {
                insns[i].OpCode = CilOpCodes.Nop;
                insns[i].Operand = null;
                insns[jumpIdx].OpCode = CilOpCodes.Br;
                insns[jumpIdx].Operand = targetInsn.CreateLabel();
            }
            else if (nonNopIntervening == 0) {
                insns[i].OpCode = CilOpCodes.Br;
                insns[i].Operand = targetInsn.CreateLabel();
            }
            else {
                // Preserve intervening setup instructions (e.g. initializing another local) and jump directly
                // to targetInsn right before dispatcherStart so control never falls through into the switch.
                insns[i].OpCode = CilOpCodes.Nop;
                insns[i].Operand = null;
                insns.Insert(dispatcherStart, new CilInstruction(CilOpCodes.Br, targetInsn.CreateLabel()));
                dispatcherStart++;
                switchIdx++;
                insns.CalculateOffsets();
            }

            rewired++;
        }

        if (rewired == 0)
            return false;

        // Check if control can fall through into dispatcherStart OR if any remaining branch targets dispatcherStart..switchIdx.
        // If either is true, the dispatcher MUST NOT be deleted.
        bool dispatcherStillReferenced = dispatcherStart == 0;
        if (!dispatcherStillReferenced) {
            int prevIdx = dispatcherStart - 1;
            while (prevIdx >= 0 && insns[prevIdx].OpCode.Code == CilCode.Nop) {
                if (HasBranchTargetInRange(insns, prevIdx, prevIdx, -1)) {
                    dispatcherStillReferenced = true;
                    break;
                }
                prevIdx--;
            }
            if (!dispatcherStillReferenced) {
                if (prevIdx < 0) {
                    dispatcherStillReferenced = true;
                }
                else {
                    var prevFlow = insns[prevIdx].OpCode.FlowControl;
                    if (prevFlow is CilFlowControl.Next or CilFlowControl.Call or CilFlowControl.ConditionalBranch or CilFlowControl.Break or CilFlowControl.Meta) {
                        dispatcherStillReferenced = true;
                    }
                }
            }
        }

        if (!dispatcherStillReferenced) {
            for (int i = 0; i < insns.Count; i++) {
                if (i >= dispatcherStart && i <= switchIdx)
                    continue;
                if (insns[i].Operand is ICilLabel l) {
                    int t = ResolveTargetIndex(insns, l);
                    if (t >= dispatcherStart && t <= switchIdx) {
                        dispatcherStillReferenced = true;
                        break;
                    }
                }
                if (insns[i].Operand is IList<ICilLabel> list && list.Any(l2 => {
                    int t = ResolveTargetIndex(insns, l2);
                    return t >= dispatcherStart && t <= switchIdx;
                })) {
                    dispatcherStillReferenced = true;
                    break;
                }
            }
        }

        if (!dispatcherStillReferenced) {
            for (int k = dispatcherStart; k <= switchIdx; k++) {
                insns[k].OpCode = CilOpCodes.Nop;
                insns[k].Operand = null;
            }
            switchEliminated = true;
        }

        return true;
    }

    private static bool HasBranchTargetInRange(CilInstructionCollection insns, int rangeStart, int rangeEnd, int extraIdx) {
        for (int i = 0; i < insns.Count; i++) {
            if (insns[i].Operand is ICilLabel l) {
                int t = ResolveTargetIndex(insns, l);
                if ((t >= rangeStart && t <= rangeEnd) || (extraIdx >= 0 && t == extraIdx))
                    return true;
            }
            else if (insns[i].Operand is IList<ICilLabel> list) {
                foreach (var l2 in list) {
                    int t = ResolveTargetIndex(insns, l2);
                    if ((t >= rangeStart && t <= rangeEnd) || (extraIdx >= 0 && t == extraIdx))
                        return true;
                }
            }
        }
        return false;
    }

    /// <summary>
    /// Evaluates a pure constant-expression stack sequence ending at <paramref name="endIdx"/>:
    /// supports single `ldc.i4 C` or binary `ldc.i4 A; ldc.i4 B; (xor|add|sub|mul|and|or)`.
    /// </summary>
    private static bool TryEvalConstantBackward(CilInstructionCollection insns, int endIdx, out int value, out int startIdx) {
        value = 0;
        startIdx = endIdx;
        if (endIdx < 0)
            return false;

        // Skip leading nops backward
        while (endIdx >= 0 && insns[endIdx].OpCode.Code == CilCode.Nop)
            endIdx--;
        if (endIdx < 0)
            return false;

        if (insns[endIdx].IsLdcI4()) {
            value = insns[endIdx].GetLdcI4Constant();
            startIdx = endIdx;
            return true;
        }

        // Binary constant expression: `ldc.i4 A; ldc.i4 B; op`
        if (endIdx >= 2 && insns[endIdx].OpCode.Code is CilCode.Xor or CilCode.Add or CilCode.Sub or CilCode.Mul or CilCode.And or CilCode.Or) {
            int bIdx = endIdx - 1;
            while (bIdx >= 0 && insns[bIdx].OpCode.Code == CilCode.Nop) bIdx--;
            int aIdx = bIdx - 1;
            while (aIdx >= 0 && insns[aIdx].OpCode.Code == CilCode.Nop) aIdx--;

            if (aIdx >= 0 && insns[aIdx].IsLdcI4() && insns[bIdx].IsLdcI4()) {
                int a = insns[aIdx].GetLdcI4Constant();
                int b = insns[bIdx].GetLdcI4Constant();
                value = insns[endIdx].OpCode.Code switch {
                    CilCode.Xor => a ^ b,
                    CilCode.Add => unchecked(a + b),
                    CilCode.Sub => unchecked(a - b),
                    CilCode.Mul => unchecked(a * b),
                    CilCode.And => a & b,
                    CilCode.Or => a | b,
                    _ => 0
                };
                startIdx = aIdx;
                return true;
            }
        }

        return false;
    }

    private static void RemoveUnreachableInstructions(CilInstructionCollection insns, CilMethodBody body) {
        if (insns.Count == 0)
            return;

        // BFS from entry (index 0) and all exception handler boundaries
        var reachable = new bool[insns.Count];
        var queue = new Queue<int>();
        reachable[0] = true;
        queue.Enqueue(0);

        foreach (var eh in body.ExceptionHandlers) {
            foreach (var lbl in new[] { eh.TryStart, eh.HandlerStart, eh.FilterStart }) {
                if (lbl is not null) {
                    int idx = ResolveTargetIndex(insns, lbl);
                    if (idx >= 0 && !reachable[idx]) {
                        reachable[idx] = true;
                        queue.Enqueue(idx);
                    }
                }
            }
        }

        while (queue.Count > 0) {
            int idx = queue.Dequeue();
            var ins = insns[idx];
            var flow = ins.OpCode.FlowControl;

            if (ins.Operand is ICilLabel target) {
                int tIdx = ResolveTargetIndex(insns, target);
                if (tIdx >= 0 && !reachable[tIdx]) {
                    reachable[tIdx] = true;
                    queue.Enqueue(tIdx);
                }
            }
            else if (ins.Operand is IList<ICilLabel> targets) {
                foreach (var t in targets) {
                    int tIdx = ResolveTargetIndex(insns, t);
                    if (tIdx >= 0 && !reachable[tIdx]) {
                        reachable[tIdx] = true;
                        queue.Enqueue(tIdx);
                    }
                }
            }

            bool fallsThrough = flow is CilFlowControl.Next or CilFlowControl.Call or CilFlowControl.ConditionalBranch or CilFlowControl.Break or CilFlowControl.Meta;
            if (fallsThrough && idx + 1 < insns.Count && !reachable[idx + 1]) {
                reachable[idx + 1] = true;
                queue.Enqueue(idx + 1);
            }
        }

        // Preserve instructions referenced by EH End labels so EH ranges stay valid
        var ehProtected = new HashSet<int>();
        foreach (var eh in body.ExceptionHandlers) {
            foreach (var lbl in new[] { eh.TryStart, eh.TryEnd, eh.HandlerStart, eh.HandlerEnd, eh.FilterStart }) {
                if (lbl is not null) {
                    int idx = ResolveTargetIndex(insns, lbl);
                    if (idx >= 0) ehProtected.Add(idx);
                }
            }
        }

        // Remove unreachable instructions and redundant nops not targeted by labels
        var referencedIndices = new HashSet<int>(ehProtected);
        for (int i = 0; i < insns.Count; i++) {
            if (!reachable[i]) continue;
            if (insns[i].Operand is ICilLabel l) {
                int t = ResolveTargetIndex(insns, l);
                if (t >= 0) referencedIndices.Add(t);
            }
            else if (insns[i].Operand is IList<ICilLabel> list) {
                foreach (var l2 in list) {
                    int t = ResolveTargetIndex(insns, l2);
                    if (t >= 0) referencedIndices.Add(t);
                }
            }
        }

        // Rebuild only reachable (and EH-protected) instructions while retargeting labels to kept instruction instances
        var kept = new List<CilInstruction>(insns.Count);
        for (int i = 0; i < insns.Count; i++) {
            if (!reachable[i] && !ehProtected.Contains(i))
                continue;
            if (insns[i].OpCode.Code == CilCode.Nop && !referencedIndices.Contains(i))
                continue;
            kept.Add(insns[i]);
        }

        if (kept.Count > 0 && kept.Count < insns.Count) {
            insns.Clear();
            foreach (var k in kept)
                insns.Add(k);
        }
    }

    private static int SkipNops(CilInstructionCollection insns, int start) {
        int i = start;
        while (i < insns.Count && insns[i].OpCode.Code == CilCode.Nop)
            i++;
        return i;
    }

    private static bool IsConstant(CilInstruction ins, int expected) =>
        ins.IsLdcI4() && ins.GetLdcI4Constant() == expected;

    private static int ResolveTargetIndex(CilInstructionCollection insns, ICilLabel label) {
        if (label is CilInstructionLabel il && il.Instruction is not null) {
            return insns.IndexOf(il.Instruction);
        }
        int offset = label.Offset;
        for (int i = 0; i < insns.Count; i++) {
            if (insns[i].Offset == offset)
                return i;
        }
        return -1;
    }
}
