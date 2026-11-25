using AsmResolver.DotNet.Signatures;

namespace de4vmp.Core.Architecture.Annotations.Variables;

public interface IVariable {
    public TypeSignature Signature { get; }
    bool IsArgument { get; }
}