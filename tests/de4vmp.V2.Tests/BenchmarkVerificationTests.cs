using System.Reflection;
using System.Runtime.Loader;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using de4vmp.V2.Models;
using de4vmp.V2.Tests.Fixtures;
using de4vmp.V2.Translation;
using Xunit;

namespace de4vmp.V2.Tests;

public sealed class BenchmarkVerificationTests {
    private sealed class CollectibleContext : AssemblyLoadContext {
        public CollectibleContext() : base(isCollectible: true) { }
        protected override Assembly? Load(AssemblyName assemblyName) => null;
    }

    [Theory]
    [InlineData(SyntheticTier.Tier1_Clean8BitTable)]
    [InlineData(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic)]
    [InlineData(SyntheticTier.Tier3_CffAndOpaquePredicates)]
    [InlineData(SyntheticTier.Tier4_MultiEntryObjectsAndEh)]
    public void Devirtualize_SyntheticTier_Achieves100PercentAccuracyAndBehavioralEquivalence(SyntheticTier tier) {
        string workDir = Path.Combine(Path.GetTempPath(), "de4vmp-v2-bench", $"{tier}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);
        try {
            string virtPath = Path.Combine(workDir, $"Virt_{tier}.dll");
            string devirtPath = Path.Combine(workDir, $"Devirt_{tier}.dll");

            // 1. Generate self-authored synthetic fixture + GroundTruth
            var compiler = new SyntheticVmCompiler();
            var truth = compiler.Generate(tier, virtPath);

            // 2. Run V2Devirtualizer purely statically + bounded sandboxed emulation (ZERO host CLR execution of virtPath)
            var module = ModuleDefinition.FromFile(virtPath);
            var devirtualizer = new V2Devirtualizer();
            var metrics = devirtualizer.Devirtualize(module);

            // 3. Assert 100% Handler Precision (0 silent misclassifications) and 100% Recall against GroundTruth
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersDiscovered);
            Assert.Equal(0, metrics.UnknownHandlers);
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersClassified);

            foreach (var (key, expectedOp) in truth.OpcodeMap) {
                Assert.True(metrics.Handlers.TryGetValue(key, out var resolved), $"Missing handler key 0x{key:X8}");
                Assert.Equal(expectedOp, resolved!.SemanticOp);
            }

            // 4. Assert CFF unflattening actually eliminated switch dispatchers on Tiers 3 & 4
            if (tier >= SyntheticTier.Tier3_CffAndOpaquePredicates) {
                Assert.True(metrics.CffSwitchesEliminated > 0, "Expected CFF switch dispatchers to be eliminated on Tier 3+.");
            }

            // 5. Assert every virtualized method was discovered and recompiled
            Assert.True(truth.VirtualizedMethods.Count == metrics.MethodsDiscovered,
                $"Expected {truth.VirtualizedMethods.Count} discovered methods, got {metrics.MethodsDiscovered}. Diagnostics:\n{string.Join("\n", metrics.Diagnostics)}");
            Assert.True(truth.VirtualizedMethods.Count == metrics.MethodsDevirtualized,
                $"Expected {truth.VirtualizedMethods.Count} devirtualized methods, got {metrics.MethodsDevirtualized}. Diagnostics:\n{string.Join("\n", metrics.Diagnostics)}");

            // 6. Write devirtualized PE assembly and verify it loads + executes bit-identically to ReferenceSuite!
            module.Write(devirtPath);

            var alc = new CollectibleContext();
            try {
                var devirtAsm = alc.LoadFromAssemblyPath(devirtPath);
                var targetType = devirtAsm.GetType("SyntheticFixture.VirtualizedTargets", throwOnError: true)!;

                VerifyDifferentialEquivalence(targetType, tier);
            }
            finally {
                alc.Unload();
            }
        }
        finally {
            try { Directory.Delete(workDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void FailClosed_WhenHandlerIsUnknown_RefusesToEmitCorruptedMethod() {
        string workDir = Path.Combine(Path.GetTempPath(), "de4vmp-v2-failclosed", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workDir);
        try {
            string virtPath = Path.Combine(workDir, "Virt_Unknown.dll");
            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic, virtPath);

            // Tamper with the Add handler's core method so it returns an unrecognized formula (a * 3 + b * 7 + 11)
            var module = ModuleDefinition.FromFile(virtPath);
            var vmType = module.TopLevelTypes.First(t => t.Name == "VmRuntime");
            var addCore = vmType.Methods.First(m => m.Name == "H_05_Core");
            var body = addCore.CilMethodBody!;
            body.Instructions.Clear();
            body.Instructions.Add(CilOpCodes.Ldarg_1);
            body.Instructions.Add(CilOpCodes.Ldc_I4, 3);
            body.Instructions.Add(CilOpCodes.Mul);
            body.Instructions.Add(CilOpCodes.Ldarg_2);
            body.Instructions.Add(CilOpCodes.Ldc_I4, 7);
            body.Instructions.Add(CilOpCodes.Mul);
            body.Instructions.Add(CilOpCodes.Add);
            body.Instructions.Add(CilOpCodes.Ldc_I4, 11);
            body.Instructions.Add(CilOpCodes.Add);
            body.Instructions.Add(CilOpCodes.Ret);

            var metrics = new V2Devirtualizer().Devirtualize(module);

            // Must classify the tampered handler as Unknown (fail-closed!) and refuse to emit methods that use it
            Assert.Equal(1, metrics.UnknownHandlers);
            Assert.True(metrics.MethodsDevirtualized < metrics.MethodsDiscovered);
            Assert.Contains(metrics.Diagnostics, d => d.Contains("unknown/unverified handler key", StringComparison.OrdinalIgnoreCase));
        }
        finally {
            try { Directory.Delete(workDir, recursive: true); } catch { }
        }
    }

    private static void VerifyDifferentialEquivalence(Type targetType, SyntheticTier tier) {
        var rng = new Random(20261125);

        // --- AddSubMul ---
        var addSubMul = targetType.GetMethod(nameof(ReferenceSuite.AddSubMul))!;
        int[] edgeInts = [0, 1, -1, 42, -99, 1000, -1000, short.MaxValue, short.MinValue];
        foreach (int a in edgeInts) {
            foreach (int b in edgeInts) {
                Assert.Equal(ReferenceSuite.AddSubMul(a, b), (int)addSubMul.Invoke(null, [a, b])!);
            }
        }
        for (int i = 0; i < 100; i++) {
            int a = rng.Next(-100_000, 100_000), b = rng.Next(-100_000, 100_000);
            Assert.Equal(ReferenceSuite.AddSubMul(a, b), (int)addSubMul.Invoke(null, [a, b])!);
        }

        // --- XorShiftMix ---
        var xorShift = targetType.GetMethod(nameof(ReferenceSuite.XorShiftMix))!;
        for (int i = 0; i < 100; i++) {
            int x = rng.Next(int.MinValue, int.MaxValue), y = rng.Next(int.MinValue, int.MaxValue);
            Assert.Equal(ReferenceSuite.XorShiftMix(x, y), (int)xorShift.Invoke(null, [x, y])!);
        }

        // --- Clamp ---
        var clamp = targetType.GetMethod(nameof(ReferenceSuite.Clamp))!;
        for (int i = 0; i < 100; i++) {
            int min = rng.Next(-500, 500), max = min + rng.Next(0, 500), v = rng.Next(-1000, 1000);
            Assert.Equal(ReferenceSuite.Clamp(v, min, max), (int)clamp.Invoke(null, [v, min, max])!);
        }

        // --- SumRange ---
        var sumRange = targetType.GetMethod(nameof(ReferenceSuite.SumRange))!;
        foreach (int n in new[] { -5, 0, 1, 2, 10, 50, 100 }) {
            Assert.Equal(ReferenceSuite.SumRange(n), (int)sumRange.Invoke(null, [n])!);
        }

        // --- Gcd ---
        var gcd = targetType.GetMethod(nameof(ReferenceSuite.Gcd))!;
        foreach (var (a, b) in new[] { (0, 0), (0, 15), (15, 0), (48, 18), (-48, 18), (1071, 462), (17, 13) }) {
            Assert.Equal(ReferenceSuite.Gcd(a, b), (int)gcd.Invoke(null, [a, b])!);
        }

        // --- ClassifyScore ---
        var classify = targetType.GetMethod(nameof(ReferenceSuite.ClassifyScore))!;
        foreach (int s in new[] { -10, -1, 0, 49, 50, 79, 80, 100 }) {
            Assert.Equal(ReferenceSuite.ClassifyScore(s), (int)classify.Invoke(null, [s])!);
        }

        if (tier >= SyntheticTier.Tier4_MultiEntryObjectsAndEh) {
            // --- SumArray ---
            var sumArray = targetType.GetMethod(nameof(ReferenceSuite.SumArray))!;
            foreach (var arr in new[] { Array.Empty<int>(), [5], [1, -2, 3, 4, -5, 100] }) {
                Assert.Equal(ReferenceSuite.SumArray(arr), (int)sumArray.Invoke(null, [arr])!);
            }

            // --- CounterIncrement (ldfld + callvirt + state mutation) ---
            var counterInc = targetType.GetMethod(nameof(ReferenceSuite.CounterIncrement))!;
            var c1 = new ReferenceCounter(10);
            var c2 = new ReferenceCounter(10);
            Assert.Equal(ReferenceSuite.CounterIncrement(c1, 7), (int)counterInc.Invoke(null, [c2, 7])!);
            Assert.Equal(c1.Value, c2.Value);

            // --- MakeCounter (newobj + ldfld + stfld) ---
            var makeCounter = targetType.GetMethod(nameof(ReferenceSuite.MakeCounter))!;
            var expectedCounter = ReferenceSuite.MakeCounter(25);
            var actualCounter = (ReferenceCounter)makeCounter.Invoke(null, [25])!;
            Assert.Equal(expectedCounter.Value, actualCounter.Value);

            // --- SafeDivide (try/catch DivideByZeroException) ---
            var safeDivide = targetType.GetMethod(nameof(ReferenceSuite.SafeDivide))!;
            Assert.Equal(ReferenceSuite.SafeDivide(20, 4), (int)safeDivide.Invoke(null, [20, 4])!);
            Assert.Equal(ReferenceSuite.SafeDivide(20, 0), (int)safeDivide.Invoke(null, [20, 0])!);

            // --- TryFinallyAccumulate (try/finally) ---
            var tryFinally = targetType.GetMethod(nameof(ReferenceSuite.TryFinallyAccumulate))!;
            Assert.Equal(ReferenceSuite.TryFinallyAccumulate(10, 5), (int)tryFinally.Invoke(null, [10, 5])!);
            Assert.Equal(ReferenceSuite.TryFinallyAccumulate(-3, 8), (int)tryFinally.Invoke(null, [-3, 8])!);
        }
    }
}
