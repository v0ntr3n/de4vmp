using AsmResolver.DotNet;

namespace de4vmp.V2.Models;

/// <summary>
/// Semantic classification of a managed VM handler.
/// Policy: fail-closed (Unknown must never be silently guessed).
/// </summary>
public enum SemanticOp {
    Unknown = 0,
    Nop,
    LdcI4,
    LdArg,
    LdLoc,
    StLoc,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Xor,
    And,
    Or,
    Shl,
    Shr,
    Neg,
    Ceq,
    Clt,
    Cgt,
    Br,
    BrTrue,
    BrFalse,
    Ret,
    NewObj,
    LdFld,
    StFld,
    Call,
    CallVirt,
    LdElemI4,
    StElemI4,
    LdLen,
    Box,
    UnboxAny,
    EnterTry,
    Leave,
    EndFinally
}

public sealed record ResolvedHandler(
    uint OpcodeKey,
    MethodDefinition HandlerMethod,
    SemanticOp SemanticOp,
    string Evidence,
    int OriginalInstructionCount,
    int UnflattenedInstructionCount);

public sealed record VerifiedCallSite(
    MethodDefinition Caller,
    MethodDefinition VmEntry,
    int InstructionIndex,
    int BytecodeOffset);

public sealed record VmDiscoveryResult(
    TypeDefinition VmType,
    IReadOnlyList<MethodDefinition> EntryMethods,
    IReadOnlyDictionary<uint, MethodDefinition> RawHandlers,
    byte[] BytecodeBlob,
    uint RollingKeySeed,
    uint RollingKeyStep,
    bool Is32BitKeyed,
    int EmulationStepsUsed);

public sealed record DevirtualizationMetrics(
    int MethodsDiscovered,
    int MethodsDevirtualized,
    int HandlersDiscovered,
    int HandlersClassified,
    int UnknownHandlers,
    int CffSwitchesEliminated,
    IReadOnlyDictionary<uint, ResolvedHandler> Handlers,
    IReadOnlyList<string> Diagnostics);
