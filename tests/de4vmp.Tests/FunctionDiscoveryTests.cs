using AsmResolver.DotNet;
using de4vmp.Core.Services;
using Xunit;

namespace de4vmp.Tests;

public class FunctionDiscoveryTests {
    public class CandidateVm {
        public readonly Dictionary<uint, Action> handlers = new();
        public object Entry(object value, int offset) => value;
    }
    public class NonCandidate {
        public object Entry(object value, int offset) => value;
    }
    public static object CandidateCall(CandidateVm vm, object arg) => vm.Entry(arg, 123456);
    public static object DecoyCall(NonCandidate vm, object arg) => vm.Entry(arg, 123456);
    public static object VariableCall(CandidateVm vm, object arg, int offset) => vm.Entry(arg, offset);

    [Fact]
    public void FindsOnlyStructurallyMatchingConstantCallSites() {
        var module = ModuleDefinition.FromFile(typeof(FunctionDiscoveryTests).Assembly.Location);
        var type = module.GetAllTypes().Single(t => t.Name == nameof(FunctionDiscoveryTests));
        var candidates = FunctionService.FindUInt32VmCandidates(type.Methods).ToArray();
        var candidate = Assert.Single(candidates);
        Assert.Equal(nameof(CandidateCall), candidate.Caller.Name?.ToString());
        Assert.Equal(nameof(CandidateVm.Entry), candidate.Entry.Name?.ToString());
        Assert.Equal(123456u, candidate.Operand);
    }
}
