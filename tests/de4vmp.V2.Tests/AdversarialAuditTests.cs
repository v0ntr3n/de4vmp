using System.Reflection;
using System.Runtime.Loader;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using de4vmp.V2.Analysis;
using de4vmp.V2.Emulation;
using de4vmp.V2.Models;
using de4vmp.V2.Tests.Fixtures;
using de4vmp.V2.Translation;
using Xunit;
using FieldAttributes = AsmResolver.PE.DotNet.Metadata.Tables.FieldAttributes;
using MethodAttributes = AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes;
using MethodImplAttributes = AsmResolver.PE.DotNet.Metadata.Tables.MethodImplAttributes;
using TypeAttributes = AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes;

namespace de4vmp.V2.Tests;

/// <summary>
/// Adversarial synthetic fixtures &amp; differential tests probing architectural limitations
/// not covered by the Tier 1-4 benchmark suite.
/// Every test asserts honest, fail-closed or empirically observed outcomes without weakening assertions.
/// </summary>
public sealed class AdversarialAuditTests {
    private sealed class CollectibleContext : AssemblyLoadContext {
        public CollectibleContext() : base(isCollectible: true) { }
        protected override Assembly? Load(AssemblyName assemblyName) => null;
    }

    private static readonly HashSet<SemanticOp> PureProbedOps = [
        SemanticOp.Add, SemanticOp.Sub, SemanticOp.Mul, SemanticOp.Div, SemanticOp.Rem,
        SemanticOp.Xor, SemanticOp.And, SemanticOp.Or, SemanticOp.Shl, SemanticOp.Shr,
        SemanticOp.Neg, SemanticOp.Ceq, SemanticOp.Clt, SemanticOp.Cgt
    ];

    private static readonly string[] KnownEnglishHelperNames = [
        "ReadI4", "Push", "Pop", "GetArg", "GetLoc", "SetLoc",
        "Jump", "JumpIfTrue", "JumpIfFalse", "Halt",
        "VmNewObj", "VmLdFld", "VmStFld", "VmCall", "VmCallVirt",
        "VmLdElemI4", "VmStElemI4", "VmLdLen", "VmLeave", "VmEndFinally", "Op_Nop"
    ];

    // =========================================================================
    // 1. Obfuscated / Renamed VM Helper Methods & Reflection MetadataToken Discovery
    // =========================================================================

    [Fact]
    public void RenamedVmHelpers_Achieves100PercentClassificationAndDifferentialEquivalence() {
        string workDir = CreateTempDir("renamed-helpers");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier2.dll");
            string obfPath = Path.Combine(workDir, "Virt_Tier2_RenamedHelpers.dll");
            string devirtPath = Path.Combine(workDir, "Devirt_Tier2_RenamedHelpers.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic, virtPath);
            var module = ModuleDefinition.FromFile(virtPath);
            var vmType = module.TopLevelTypes.First(t => t.Name == "VmRuntime");

            // Rename all 21 English-named VM helper methods to opaque names (m_01 .. m_21)
            int renamed = 0;
            foreach (string helperName in KnownEnglishHelperNames) {
                var helper = vmType.Methods.FirstOrDefault(m => m.Name == helperName);
                Assert.NotNull(helper);
                renamed++;
                helper!.Name = $"m_{renamed:D2}";
            }
            Assert.Equal(KnownEnglishHelperNames.Length, renamed);

            // Persist & reload to verify against a genuine PE artifact
            module.Write(obfPath);
            var reloaded = ModuleDefinition.FromFile(obfPath);

            var metrics = new V2Devirtualizer().Devirtualize(reloaded);

            // 100% handler discovery and 100% name-invariant classification (33/33, 0 Unknown)
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersDiscovered);
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersClassified);
            Assert.Equal(0, metrics.UnknownHandlers);

            foreach (var (key, expectedOp) in truth.OpcodeMap) {
                Assert.True(metrics.Handlers.TryGetValue(key, out var resolved));
                Assert.Equal(expectedOp, resolved!.SemanticOp);
            }

            // 100% method discovery & devirtualization (6/6)
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDevirtualized);

            // Verify 100% differential behavioral equivalence against ReferenceSuite
            reloaded.Write(devirtPath);
            BenchmarkVerificationTests.VerifyWithIlVerify(devirtPath, minVerifiedMethods: truth.VirtualizedMethods.Count);
            VerifyTier2DifferentialEquivalence(devirtPath);
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void ReflectionMetadataTokenDiscovery_GClass105CctorLoop_Discovers100PercentOfHandlers() {
        string workDir = CreateTempDir("reflection-token-vm");
        try {
            string dllPath = Path.Combine(workDir, "ReflectionTokenVm.dll");
            var (module, expectedHandlerNames) = BuildReflectionMetadataTokenVmModule();

            // Write and reload so every method has its real ECMA-335 0x0600XXXX MetadataToken
            module.Write(dllPath);
            var reloaded = ModuleDefinition.FromFile(dllPath);

            var vmType = reloaded.TopLevelTypes.First(t => t.Name == "GClass105");
            var expectedByToken = new Dictionary<uint, string>();
            foreach (string hName in expectedHandlerNames) {
                var hm = vmType.Methods.First(m => m.Name == hName);
                uint tok = hm.MetadataToken.ToUInt32();
                Assert.NotEqual(0u, tok);
                expectedByToken[tok] = hName;
            }

            var diagnostics = new List<string>();
            var discovery = new V2Devirtualizer().DiscoverVm(reloaded, diagnostics);

            Assert.NotNull(discovery);
            Assert.Equal(expectedByToken.Count, discovery!.RawHandlers.Count);

            foreach (var (tok, expectedName) in expectedByToken) {
                Assert.True(discovery.RawHandlers.TryGetValue(tok, out var discoveredMethod),
                    $"Expected handler token 0x{tok:X8} ({expectedName}) to be discovered.");
                Assert.Equal(expectedName, discoveredMethod!.Name!.Value);
            }
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    // =========================================================================
    // 2. Complex Multi-Op rem.un CFF State Machine (mirroring GClass105::.ctor)
    // =========================================================================

    [Fact]
    public void ComplexMultiOpRemUnCff_BailsOutWithoutCorruptingMethod() {
        string workDir = CreateTempDir("complex-remun-cff");
        try {
            // Formula matching GClass105::.ctor style:
            //   ldloc s; conv.u2; stloc t; ldc.i4 K1; ldc.i4 K2; ldloc t; ldloc s; mul; xor; xor; ldc.i4 7; rem.un; switch (...)
            const int K1 = unchecked((int)0x5F3759DF);
            const int K2 = unchecked((int)0x2B992DDF);

            static int ComputeCase(int s) {
                int t = (ushort)s;
                int mixed = K1 ^ (K2 ^ unchecked(t * s));
                return (int)((uint)mixed % 7u);
            }

            // Find 5 concrete state values mapping to distinct switch cases 0..4
            var stateForCase = new int[5];
            var found = new bool[5];
            for (int candidate = 100; candidate < 100_000 && found.Any(f => !f); candidate++) {
                int c = ComputeCase(candidate);
                if (c >= 0 && c < 5 && !found[c]) {
                    stateForCase[c] = candidate;
                    found[c] = true;
                }
            }
            Assert.All(found, Assert.True);

            static int ReferenceFormula(int x, int y) => unchecked(((x + y) * 3) ^ (x - y));

            var (module, method) = BuildComplexRemUnCffModule(K1, K2, stateForCase);

            var unflattener = new CffUnflattener();
            var cffResult = unflattener.Unflatten(method.CilMethodBody!);

            // Empirically verify CffUnflattener cannot parse the multi-op conv.u2/mul/xor/rem.un dispatcher
            Assert.Equal(0, cffResult.SwitchesEliminated);
            Assert.False(cffResult.WasFlattened);
            Assert.Contains(method.CilMethodBody!.Instructions, i => i.OpCode.Code == CilCode.Switch);

            // Verify via differential execution that CffUnflattener did NOT corrupt the method when bailing out
            method.CilMethodBody.ComputeMaxStack();
            string outPath = Path.Combine(workDir, "ComplexRemUnCff.dll");
            module.Write(outPath);

            var alc = new CollectibleContext();
            try {
                var asm = alc.LoadFromAssemblyPath(outPath);
                var type = asm.GetType("AdversarialFixture.ComplexCffTarget", throwOnError: true)!;
                var mi = type.GetMethod("Compute", BindingFlags.Public | BindingFlags.Static)!;

                var rng = new Random(20261125);
                for (int i = 0; i < 50; i++) {
                    int x = i < 5 ? (i - 2) * 1000 : rng.Next(-100_000, 100_000);
                    int y = i < 5 ? (2 - i) * 777 : rng.Next(-100_000, 100_000);
                    int actual = (int)mi.Invoke(null, [x, y])!;
                    Assert.Equal(ReferenceFormula(x, y), actual);
                }
            }
            finally {
                alc.Unload();
            }
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    // =========================================================================
    // 3. BoundedCilEmulator: Cross-Type Registration, Unsupported Opcode, 64-bit Truncation
    // =========================================================================

    [Fact]
    public void BoundedEmulator_UnsupportedOpcodeLdlocaS_StopsAndCapturesZeroHandlers() {
        var (module, vmCtor) = BuildVmCtorWithUnsupportedOpcodeLdlocaS();
        var emulator = new BoundedCilEmulator();

        var snap = emulator.EmulateMethod(vmCtor);

        Assert.False(snap.CompletedNormally);
        Assert.NotNull(snap.StopReason);
        Assert.Contains("Ldloca", snap.StopReason!, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(snap.CapturedHandlers);
    }

    [Fact]
    public void BoundedEmulator_CrossTypeHelperRegistration_FailsClosedOnUnmodeledCall() {
        var (module, vmCtor) = BuildVmCtorWithCrossTypeHelperRegistration();
        var emulator = new BoundedCilEmulator();

        var snap = emulator.EmulateMethod(vmCtor);

        // BoundedCilEmulator only steps into callees on the SAME DeclaringType and allowlisted BCL hooks.
        // Calls to unmodeled cross-type helpers must fail closed instead of silently returning 0.
        Assert.False(snap.CompletedNormally);
        Assert.NotNull(snap.StopReason);
        Assert.Contains("Unmodeled call", snap.StopReason!, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(snap.CapturedHandlers);
    }

    [Theory]
    [InlineData("Add", 0x0000_0001_0000_0010L, 0x0000_0002_0000_0020L, 0x0000_0003_0000_0030L)]
    [InlineData("Sub", 0x0000_0005_0000_0030L, 0x0000_0002_0000_0010L, 0x0000_0003_0000_0020L)]
    [InlineData("Xor", 0x0000_0003_0000_000FL, 0x0000_0001_0000_00F0L, 0x0000_0002_0000_00FFL)]
    public void BoundedEmulator_Int64Arithmetic_PreservesFull64BitResult(string opName, long a, long b, long expectedTrueInt64) {
        CilOpCode opCode = opName switch {
            "Add" => CilOpCodes.Add,
            "Sub" => CilOpCodes.Sub,
            "Xor" => CilOpCodes.Xor,
            _ => throw new ArgumentOutOfRangeException(nameof(opName))
        };

        var method = BuildInt64BinaryOpMethod(opName, opCode, a, b);
        var emulator = new BoundedCilEmulator();

        var snap = emulator.EmulateMethod(method);

        Assert.True(snap.CompletedNormally);
        long actual = Assert.IsType<long>(snap.ReturnValue);
        Assert.Equal(expectedTrueInt64, actual);
    }

    [Fact]
    public void BoundedEmulator_InstanceMethodLdargAndObjectBeq_BehavesAccurately() {
        var module = CreateFreshNet8Module("InstanceLdargBeq");
        var importer = module.DefaultImporter;
        var corlib = module.CorLibTypeFactory;

        var type = new TypeDefinition("AdversarialVm", "InstanceHelper", TypeAttributes.Public | TypeAttributes.Class,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(type);

        // Instance method: int CompareAndRead(object obj, int val) => obj == null ? -1 : val;
        var method = new MethodDefinition("CompareAndRead", MethodAttributes.Public | MethodAttributes.HideBySig,
            MethodSignature.CreateInstance(corlib.Int32, [corlib.Object, corlib.Int32]));
        type.Methods.Add(method);

        var body = new CilMethodBody();
        var retNeg = new CilInstruction(CilOpCodes.Ldc_I4_M1);
        // Use long-form Ldarg (which goes through GetArgIndex) on both parameter 0 (obj) and parameter 1 (val)
        body.Instructions.Add(CilOpCodes.Ldarg, method.Parameters[0]);
        body.Instructions.Add(CilOpCodes.Ldnull);
        body.Instructions.Add(CilOpCodes.Beq, retNeg.CreateLabel());
        body.Instructions.Add(CilOpCodes.Ldarg, method.Parameters[1]);
        body.Instructions.Add(CilOpCodes.Ret);
        body.Instructions.Add(retNeg);
        body.Instructions.Add(CilOpCodes.Ret);
        method.CilMethodBody = body;

        var emulator = new BoundedCilEmulator();

        // Non-null object != null -> must return val (42), not -1!
        var snapNonNull = emulator.EmulateMethod(method, initialArgs: [new object(), 42]);
        Assert.True(snapNonNull.CompletedNormally);
        Assert.Equal(42, Assert.IsType<int>(snapNonNull.ReturnValue));

        // Null object == null -> must return -1!
        var snapNull = emulator.EmulateMethod(method, initialArgs: [null, 42]);
        Assert.True(snapNull.CompletedNormally);
        Assert.Equal(-1, Assert.IsType<int>(snapNull.ReturnValue));
    }

    // =========================================================================
    // 4. Computed Call-Site Offsets & Non-ManifestResource Bytecode
    // =========================================================================

    [Fact]
    public void ComputedCallSiteOffsets_DiscoveredAndDevirtualizedWithDifferentialEquivalence() {
        string workDir = CreateTempDir("computed-callsite");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier2.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier2_ComputedOffsets.dll");
            string devirtPath = Path.Combine(workDir, "Devirt_Tier2_ComputedOffsets.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic, virtPath);
            var module = ModuleDefinition.FromFile(virtPath);
            var targetType = module.TopLevelTypes.First(t => t.Name == "VirtualizedTargets");

            const int mask = 0x1337;
            int patchedCallSites = 0;

            foreach (var m in targetType.Methods) {
                var insns = m.CilMethodBody!.Instructions;
                insns.ExpandMacros();
                for (int i = 1; i < insns.Count; i++) {
                    if (insns[i].OpCode.Code is CilCode.Call or CilCode.Callvirt &&
                        insns[i].Operand is MethodDefinition callee &&
                        callee.Name?.Value.StartsWith("Execute_") == true &&
                        insns[i - 1].IsLdcI4()) {
                        int offset = insns[i - 1].GetLdcI4Constant();
                        // Replace `ldc.i4 offset; call Execute_0` with `ldc.i4 (offset ^ mask); ldc.i4 mask; xor; call Execute_0`
                        insns[i - 1].OpCode = CilOpCodes.Ldc_I4;
                        insns[i - 1].Operand = offset ^ mask;
                        insns.Insert(i, new CilInstruction(CilOpCodes.Ldc_I4, mask));
                        insns.Insert(i + 1, new CilInstruction(CilOpCodes.Xor));
                        patchedCallSites++;
                        break;
                    }
                }
                m.CilMethodBody.ComputeMaxStack();
            }
            Assert.Equal(truth.VirtualizedMethods.Count, patchedCallSites);

            module.Write(modPath);
            var reloaded = ModuleDefinition.FromFile(modPath);

            var metrics = new V2Devirtualizer().Devirtualize(reloaded);

            // Handlers are 100% discovered and classified
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersDiscovered);
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersClassified);

            // Computed call-site offsets are evaluated structurally: 6/6 discovered & 6/6 devirtualized!
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDevirtualized);

            reloaded.Write(devirtPath);
            BenchmarkVerificationTests.VerifyWithIlVerify(devirtPath, minVerifiedMethods: truth.VirtualizedMethods.Count);
            VerifyTier2DifferentialEquivalence(devirtPath);
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void NonManifestResource_RenamedResourceAndKeys_ExtractsAndDevirtualizesWithEquivalence() {
        string workDir = CreateTempDir("non-manifest-bytecode");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier2.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier2_NoVmBytecodeResource.dll");
            string devirtPath = Path.Combine(workDir, "Devirt_Tier2_NoVmBytecodeResource.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic, virtPath);
            var module = ModuleDefinition.FromFile(virtPath);

            // Rename ManifestResource from "VmBytecode" to an obfuscated name, rename KeySeed/KeyStep, and clear FieldRva
            var res = module.Resources.First(r => r.Name == "VmBytecode");
            res.Name = "EncryptedBlob_9F3A";
            var vmType = module.TopLevelTypes.First(t => t.Name == "VmRuntime");
            vmType.Fields.First(f => f.Name == "KeySeed").Name = "k_a";
            vmType.Fields.First(f => f.Name == "KeyStep").Name = "k_b";
            var blobField = vmType.Fields.First(f => f.Name == "BytecodeBlob");
            blobField.FieldRva = null;
            blobField.Attributes &= ~FieldAttributes.HasFieldRva;

            module.Write(modPath);
            var reloaded = ModuleDefinition.FromFile(modPath);

            var devirt = new V2Devirtualizer();
            var diags = new List<string>();
            var discovery = devirt.DiscoverVm(reloaded, diags);

            // VM, obfuscated bytecode resource, and renamed rolling keys are all discovered structurally
            Assert.NotNull(discovery);
            Assert.NotEmpty(discovery!.BytecodeBlob);

            var metrics = devirt.Devirtualize(reloaded);
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersClassified);
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDevirtualized);

            reloaded.Write(devirtPath);
            BenchmarkVerificationTests.VerifyWithIlVerify(devirtPath, minVerifiedMethods: truth.VirtualizedMethods.Count);
            VerifyTier2DifferentialEquivalence(devirtPath);
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    // =========================================================================
    // 5. Differential Equivalence on Unflattened Tier-3-Style CFF Method
    // =========================================================================

    [Fact]
    public void CffUnflattener_Tier3StyleMethod_PreservesExactSemanticsAcross50Inputs() {
        string workDir = CreateTempDir("cff-diff-equiv");
        try {
            static int ReferenceCompute(int a, int b) {
                int t = unchecked((a * 7) ^ (b + 13));
                if (t < 0)
                    t = unchecked(-t + 5);
                return unchecked((t + (a & 0xFF)) - (b >> 1));
            }

            var (module, method) = BuildTier3StyleCffMethod();
            string flatPath = Path.Combine(workDir, "Tier3_Flattened.dll");
            string unflatPath = Path.Combine(workDir, "Tier3_Unflattened.dll");

            // 1. Write & verify the flattened assembly first (sanity baseline)
            method.CilMethodBody!.ComputeMaxStack();
            module.Write(flatPath);

            // 2. Run CffUnflattener on a freshly loaded copy
            var unflatModule = ModuleDefinition.FromFile(flatPath);
            var unflatType = unflatModule.TopLevelTypes.First(t => t.Name == "Tier3CffTarget");
            var unflatMethod = unflatType.Methods.First(m => m.Name == "Compute");

            var unflattener = new CffUnflattener();
            var cffResult = unflattener.Unflatten(unflatMethod.CilMethodBody!);

            Assert.True(cffResult.WasFlattened);
            Assert.True(cffResult.SwitchesEliminated >= 1, $"Expected >= 1 switch eliminated, got {cffResult.SwitchesEliminated}.");
            Assert.True(cffResult.FinalInstructionCount < cffResult.OriginalInstructionCount);
            Assert.DoesNotContain(unflatMethod.CilMethodBody!.Instructions, i => i.OpCode.Code == CilCode.Switch);

            unflatMethod.CilMethodBody.ComputeMaxStack();
            unflatModule.Write(unflatPath);

            // 3. Load both flattened and unflattened assemblies in collectible ALCs and test 50+ inputs
            var inputs = new List<(int A, int B)> {
                (0, 0), (1, 1), (-1, -1), (int.MaxValue / 16, int.MinValue / 16),
                (-100, 50), (42, -99), (255, 256), (-13, 0), (7, -7), (1024, -2048)
            };
            var rng = new Random(20261125);
            while (inputs.Count < 50) {
                inputs.Add((rng.Next(-100_000, 100_000), rng.Next(-100_000, 100_000)));
            }

            var flatAlc = new CollectibleContext();
            var unflatAlc = new CollectibleContext();
            try {
                var flatMi = flatAlc.LoadFromAssemblyPath(flatPath)
                    .GetType("AdversarialFixture.Tier3CffTarget", throwOnError: true)!
                    .GetMethod("Compute", BindingFlags.Public | BindingFlags.Static)!;
                var unflatMi = unflatAlc.LoadFromAssemblyPath(unflatPath)
                    .GetType("AdversarialFixture.Tier3CffTarget", throwOnError: true)!
                    .GetMethod("Compute", BindingFlags.Public | BindingFlags.Static)!;

                foreach (var (a, b) in inputs) {
                    int expected = ReferenceCompute(a, b);
                    int flatActual = (int)flatMi.Invoke(null, [a, b])!;
                    int unflatActual = (int)unflatMi.Invoke(null, [a, b])!;

                    Assert.Equal(expected, flatActual);
                    Assert.Equal(expected, unflatActual);
                }
            }
            finally {
                flatAlc.Unload();
                unflatAlc.Unload();
            }
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void CffUnflattener_DynamicPredecessorFallthrough_PreservesDispatcherAndMatchesReference50Inputs() {
        string workDir = CreateTempDir("cff-dynamic-fallthrough");
        try {
            static int ReferenceCompute(int a, int b) {
                int acc = (a & 1) == 0 ? unchecked(a + b) : unchecked(a - b);
                return unchecked(acc * 3);
            }

            var (module, method) = BuildDynamicFallthroughCffMethod();
            string outPath = Path.Combine(workDir, "DynamicFallthroughCff.dll");

            var unflattener = new CffUnflattener();
            var cffResult = unflattener.Unflatten(method.CilMethodBody!);

            // Constant back-edges from case0/case1 to case2 are rewired, leaving zero explicit branches to dispatcherStart.
            // However, `state = a & 1` falls through directly into dispatcherStart, so the switch dispatcher MUST be preserved!
            Assert.Equal(0, cffResult.SwitchesEliminated);
            Assert.Contains(method.CilMethodBody!.Instructions, i => i.OpCode.Code == CilCode.Switch);

            method.CilMethodBody.ComputeMaxStack();
            module.Write(outPath);

            var rng = new Random(20261125);
            var inputs = new List<(int A, int B)> {
                (0, 0), (1, 0), (2, 5), (3, 5), (-1, 10), (-2, 10), (int.MaxValue, -1), (int.MinValue, 1)
            };
            while (inputs.Count < 50)
                inputs.Add((rng.Next(-100_000, 100_000), rng.Next(-100_000, 100_000)));

            var alc = new CollectibleContext();
            try {
                var mi = alc.LoadFromAssemblyPath(outPath)
                    .GetType("AdversarialFixture.DynamicFallthroughTarget", throwOnError: true)!
                    .GetMethod("Compute", BindingFlags.Public | BindingFlags.Static)!;

                foreach (var (a, b) in inputs) {
                    int actual = (int)mi.Invoke(null, [a, b])!;
                    Assert.Equal(ReferenceCompute(a, b), actual);
                }
            }
            finally {
                alc.Unload();
            }
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void V2Devirtualizer_TruncatedBytecodeStream_FailsClosedWithoutThrowing() {
        string workDir = CreateTempDir("truncated-bytecode");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier1.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier1_Truncated.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier1_Clean8BitTable, virtPath);
            var module = ModuleDefinition.FromFile(virtPath);

            // Truncate the embedded VmBytecode resource to 13 bytes (12-byte header + 1 partial byte)
            var res = module.Resources.First(r => r.Name == "VmBytecode");
            byte[] original = res.GetData()!;
            byte[] truncated = original.Take(13).ToArray();
            module.Resources.Remove(res);
            module.Resources.Add(new ManifestResource("VmBytecode", AsmResolver.PE.DotNet.Metadata.Tables.ManifestResourceAttributes.Public, new DataSegment(truncated)));

            module.Write(modPath);
            var reloaded = ModuleDefinition.FromFile(modPath);

            // Must NOT throw EndOfStreamException; must fail closed cleanly with diagnostics
            var metrics = new V2Devirtualizer().Devirtualize(reloaded);
            Assert.Equal(0, metrics.MethodsDevirtualized);
            Assert.NotEmpty(metrics.Diagnostics);
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    // =========================================================================
    // Synthetic IL Fixture Builders
    // =========================================================================

    private static ModuleDefinition CreateFreshNet8Module(string name) {
        var refModule = ModuleDefinition.FromFile(typeof(ReferenceSuite).Assembly.Location);
        var module = new ModuleDefinition($"{name}.dll", refModule.CorLibTypeFactory.CorLibScope as AssemblyReference);
        var assembly = new AssemblyDefinition(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        return module;
    }

    private static (ModuleDefinition Module, MethodDefinition Method) BuildComplexRemUnCffModule(
        int k1, int k2, int[] stateForCase) {
        var module = CreateFreshNet8Module("ComplexRemUnCff");
        var importer = module.DefaultImporter;
        var int32 = module.CorLibTypeFactory.Int32;

        var targetType = new TypeDefinition("AdversarialFixture", "ComplexCffTarget",
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(targetType);

        var method = new MethodDefinition("Compute",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(int32, [int32, int32]));
        targetType.Methods.Add(method);

        var body = new CilMethodBody { InitializeLocals = true };
        var sVar = new CilLocalVariable(int32);
        var tVar = new CilLocalVariable(int32);
        var accVar = new CilLocalVariable(int32);
        var diffVar = new CilLocalVariable(int32);
        body.LocalVariables.Add(sVar);
        body.LocalVariables.Add(tVar);
        body.LocalVariables.Add(accVar);
        body.LocalVariables.Add(diffVar);

        var dispatcher = new CilInstruction(CilOpCodes.Ldloc, sVar);
        var c0 = new CilInstruction(CilOpCodes.Nop);
        var c1 = new CilInstruction(CilOpCodes.Nop);
        var c2 = new CilInstruction(CilOpCodes.Nop);
        var c3 = new CilInstruction(CilOpCodes.Nop);
        var c4 = new CilInstruction(CilOpCodes.Nop);
        var c5 = new CilInstruction(CilOpCodes.Nop);
        var c6 = new CilInstruction(CilOpCodes.Nop);

        // Initial state -> case 0
        body.Instructions.Add(CilOpCodes.Ldc_I4, stateForCase[0]);
        body.Instructions.Add(CilOpCodes.Stloc, sVar);

        // Dispatcher: ldloc s; conv.u2; stloc t; ldc.i4 K1; ldc.i4 K2; ldloc t; ldloc s; mul; xor; xor; ldc.i4 7; rem.un; switch (...)
        body.Instructions.Add(dispatcher);
        body.Instructions.Add(CilOpCodes.Conv_U2);
        body.Instructions.Add(CilOpCodes.Stloc, tVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, k1);
        body.Instructions.Add(CilOpCodes.Ldc_I4, k2);
        body.Instructions.Add(CilOpCodes.Ldloc, tVar);
        body.Instructions.Add(CilOpCodes.Ldloc, sVar);
        body.Instructions.Add(CilOpCodes.Mul);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 7);
        body.Instructions.Add(CilOpCodes.Rem_Un);
        body.Instructions.Add(CilOpCodes.Switch, new List<ICilLabel> {
            c0.CreateLabel(), c1.CreateLabel(), c2.CreateLabel(), c3.CreateLabel(),
            c4.CreateLabel(), c5.CreateLabel(), c6.CreateLabel()
        });
        body.Instructions.Add(CilOpCodes.Ldc_I4_M1);
        body.Instructions.Add(CilOpCodes.Ret);

        // Case 0: acc = x + y; s = stateForCase[1]; br dispatcher
        body.Instructions.Add(c0);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, stateForCase[1]);
        body.Instructions.Add(CilOpCodes.Stloc, sVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcher.CreateLabel());

        // Case 1: acc = acc * 3; s = stateForCase[2]; br dispatcher
        body.Instructions.Add(c1);
        body.Instructions.Add(CilOpCodes.Ldloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_3);
        body.Instructions.Add(CilOpCodes.Mul);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, stateForCase[2]);
        body.Instructions.Add(CilOpCodes.Stloc, sVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcher.CreateLabel());

        // Case 2: diff = x - y; s = stateForCase[3]; br dispatcher
        body.Instructions.Add(c2);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Sub);
        body.Instructions.Add(CilOpCodes.Stloc, diffVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, stateForCase[3]);
        body.Instructions.Add(CilOpCodes.Stloc, sVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcher.CreateLabel());

        // Case 3: acc = acc ^ diff; s = stateForCase[4]; br dispatcher
        body.Instructions.Add(c3);
        body.Instructions.Add(CilOpCodes.Ldloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldloc, diffVar);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, stateForCase[4]);
        body.Instructions.Add(CilOpCodes.Stloc, sVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcher.CreateLabel());

        // Case 4: return acc
        body.Instructions.Add(c4);
        body.Instructions.Add(CilOpCodes.Ldloc, accVar);
        body.Instructions.Add(CilOpCodes.Ret);

        // Cases 5 & 6: unreachable fallbacks
        body.Instructions.Add(c5);
        body.Instructions.Add(CilOpCodes.Ldc_I4, -999);
        body.Instructions.Add(CilOpCodes.Ret);

        body.Instructions.Add(c6);
        body.Instructions.Add(CilOpCodes.Ldc_I4, -888);
        body.Instructions.Add(CilOpCodes.Ret);

        method.CilMethodBody = body;
        return (module, method);
    }

    private static (ModuleDefinition Module, MethodDefinition VmCtor) BuildVmCtorWithUnsupportedOpcodeLdlocaS() {
        var module = CreateFreshNet8Module("UnsupportedOpcodeVm");
        var importer = module.DefaultImporter;
        var corlib = module.CorLibTypeFactory;

        var vmType = new TypeDefinition("AdversarialVm", "VmWithLdloca", TypeAttributes.Public | TypeAttributes.Class,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(vmType);

        var (delType, delCtor) = CreateDelegateType(vmType, importer, corlib);
        var (dictField, dictCtor, dictAdd) = CreateHandlerDictionary(vmType, delType, importer, corlib);

        var handler = new MethodDefinition("H_00", MethodAttributes.Private, MethodSignature.CreateInstance(corlib.Void));
        var hb = new CilMethodBody();
        hb.Instructions.Add(CilOpCodes.Ret);
        handler.CilMethodBody = hb;
        vmType.Methods.Add(handler);

        var ctor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(corlib.Void));
        vmType.Methods.Add(ctor);

        var b = new CilMethodBody { InitializeLocals = true };
        var loc0 = new CilLocalVariable(corlib.Int32);
        b.LocalVariables.Add(loc0);

        b.Instructions.Add(CilOpCodes.Ldarg_0);
        b.Instructions.Add(CilOpCodes.Newobj, dictCtor);
        b.Instructions.Add(CilOpCodes.Stfld, dictField);

        // Unsupported opcode `ldloca.s` before handler registration
        b.Instructions.Add(CilOpCodes.Ldloca_S, loc0);
        b.Instructions.Add(CilOpCodes.Pop);

        // Handler registration that will never be reached because emulator halts on ldloca.s
        b.Instructions.Add(CilOpCodes.Ldarg_0);
        b.Instructions.Add(CilOpCodes.Ldfld, dictField);
        b.Instructions.Add(CilOpCodes.Ldc_I4, 0x11223344);
        b.Instructions.Add(CilOpCodes.Ldarg_0);
        b.Instructions.Add(CilOpCodes.Ldftn, handler);
        b.Instructions.Add(CilOpCodes.Newobj, delCtor);
        b.Instructions.Add(CilOpCodes.Callvirt, dictAdd);
        b.Instructions.Add(CilOpCodes.Ret);

        ctor.CilMethodBody = b;
        return (module, ctor);
    }

    private static (ModuleDefinition Module, MethodDefinition VmCtor) BuildVmCtorWithCrossTypeHelperRegistration() {
        var module = CreateFreshNet8Module("CrossTypeHelperVm");
        var importer = module.DefaultImporter;
        var corlib = module.CorLibTypeFactory;

        var vmType = new TypeDefinition("AdversarialVm", "VmWithExternalRegistrar", TypeAttributes.Public | TypeAttributes.Class,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(vmType);

        var (delType, delCtor) = CreateDelegateType(vmType, importer, corlib);
        var (dictField, dictCtor, dictAdd) = CreateHandlerDictionary(vmType, delType, importer, corlib);

        var handler = new MethodDefinition("H_00", MethodAttributes.Public, MethodSignature.CreateInstance(corlib.Void));
        var hb = new CilMethodBody();
        hb.Instructions.Add(CilOpCodes.Ret);
        handler.CilMethodBody = hb;
        vmType.Methods.Add(handler);

        // Separate helper type that performs dictionary.Add(key, delegate)
        var registrarType = new TypeDefinition("AdversarialVm", "ExternalRegistrar",
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(registrarType);

        var registerMethod = new MethodDefinition("RegisterAll",
            MethodAttributes.Public | MethodAttributes.Static,
            MethodSignature.CreateStatic(corlib.Void, [dictField.Signature!.FieldType, vmType.ToTypeSignature()]));
        registrarType.Methods.Add(registerMethod);

        var rb = new CilMethodBody();
        rb.Instructions.Add(CilOpCodes.Ldarg_0);
        rb.Instructions.Add(CilOpCodes.Ldc_I4, 0x55667788);
        rb.Instructions.Add(CilOpCodes.Ldarg_1);
        rb.Instructions.Add(CilOpCodes.Ldftn, handler);
        rb.Instructions.Add(CilOpCodes.Newobj, delCtor);
        rb.Instructions.Add(CilOpCodes.Callvirt, dictAdd);
        rb.Instructions.Add(CilOpCodes.Ret);
        registerMethod.CilMethodBody = rb;

        var ctor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(corlib.Void));
        vmType.Methods.Add(ctor);

        var b = new CilMethodBody();
        b.Instructions.Add(CilOpCodes.Ldarg_0);
        b.Instructions.Add(CilOpCodes.Newobj, dictCtor);
        b.Instructions.Add(CilOpCodes.Stfld, dictField);
        b.Instructions.Add(CilOpCodes.Ldarg_0);
        b.Instructions.Add(CilOpCodes.Ldfld, dictField);
        b.Instructions.Add(CilOpCodes.Ldarg_0);
        b.Instructions.Add(CilOpCodes.Call, registerMethod);
        b.Instructions.Add(CilOpCodes.Ret);
        ctor.CilMethodBody = b;

        return (module, ctor);
    }

    private static MethodDefinition BuildInt64BinaryOpMethod(string name, CilOpCode opCode, long a, long b) {
        var module = CreateFreshNet8Module($"Int64_{name}");
        var importer = module.DefaultImporter;
        var int64 = module.CorLibTypeFactory.Int64;

        var t = new TypeDefinition("AdversarialVm", "Int64Math", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(t);

        var m = new MethodDefinition($"Do_{name}", MethodAttributes.Public | MethodAttributes.Static,
            MethodSignature.CreateStatic(int64));
        t.Methods.Add(m);

        var body = new CilMethodBody();
        body.Instructions.Add(CilOpCodes.Ldc_I8, a);
        body.Instructions.Add(CilOpCodes.Ldc_I8, b);
        body.Instructions.Add(opCode);
        body.Instructions.Add(CilOpCodes.Ret);
        m.CilMethodBody = body;

        return m;
    }

    private static (ModuleDefinition Module, MethodDefinition Method) BuildTier3StyleCffMethod() {
        var module = CreateFreshNet8Module("Tier3CffDiff");
        var importer = module.DefaultImporter;
        var int32 = module.CorLibTypeFactory.Int32;

        var targetType = new TypeDefinition("AdversarialFixture", "Tier3CffTarget",
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(targetType);

        var method = new MethodDefinition("Compute",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(int32, [int32, int32]));
        targetType.Methods.Add(method);

        var body = new CilMethodBody { InitializeLocals = true };
        var stateVar = new CilLocalVariable(int32);
        var opaqueVar = new CilLocalVariable(int32);
        var tVar = new CilLocalVariable(int32);
        body.LocalVariables.Add(stateVar);
        body.LocalVariables.Add(opaqueVar);
        body.LocalVariables.Add(tVar);

        var dispatcherStart = new CilInstruction(CilOpCodes.Ldloc, stateVar);
        var case0 = new CilInstruction(CilOpCodes.Nop);
        var case1 = new CilInstruction(CilOpCodes.Nop); // dead bogus block
        var case2 = new CilInstruction(CilOpCodes.Nop); // opaque predicate
        var case3 = new CilInstruction(CilOpCodes.Nop); // final stage

        // Entry: opaqueVar = 11; stateVar = 0x55 ^ 2 (= 2); falls through into dispatcherStart
        body.Instructions.Add(CilOpCodes.Ldc_I4, 11);
        body.Instructions.Add(CilOpCodes.Stloc, opaqueVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0x55 ^ 2);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0x55);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);

        // Dispatcher: ldloc stateVar; switch (case0, case1, case2, case3)
        body.Instructions.Add(dispatcherStart);
        body.Instructions.Add(CilOpCodes.Switch, new List<ICilLabel> {
            case0.CreateLabel(), case1.CreateLabel(), case2.CreateLabel(), case3.CreateLabel()
        });
        body.Instructions.Add(CilOpCodes.Br, case0.CreateLabel());

        // Case 2: Opaque predicate (opaqueVar * (opaqueVar + 1)) % 2 == 0 -> always takes brfalse -> state = 0
        body.Instructions.Add(case2);
        var setState0 = new CilInstruction(CilOpCodes.Ldc_I4_0);
        body.Instructions.Add(CilOpCodes.Ldloc, opaqueVar);
        body.Instructions.Add(CilOpCodes.Ldloc, opaqueVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_1);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Mul);
        body.Instructions.Add(CilOpCodes.Ldc_I4_2);
        body.Instructions.Add(CilOpCodes.Rem);
        body.Instructions.Add(CilOpCodes.Brfalse, setState0.CreateLabel());
        // Dead branch -> state = 1
        body.Instructions.Add(CilOpCodes.Ldc_I4_1);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcherStart.CreateLabel());
        // True branch -> state = 0
        body.Instructions.Add(setState0);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcherStart.CreateLabel());

        // Case 1: Dead bogus block that would corrupt result if ever reached
        body.Instructions.Add(case1);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0xDEAD);
        body.Instructions.Add(CilOpCodes.Stloc, tVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_3);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcherStart.CreateLabel());

        // Case 0: t = (a * 7) ^ (b + 13); state = 0x3A ^ 3 (= 3); br dispatcherStart
        body.Instructions.Add(case0);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Ldc_I4_7);
        body.Instructions.Add(CilOpCodes.Mul);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 13);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Stloc, tVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0x3A ^ 3);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0x3A);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcherStart.CreateLabel());

        // Case 3: if (t < 0) t = -t + 5; return (t + (a & 0xFF)) - (b >> 1);
        body.Instructions.Add(case3);
        var afterNeg = new CilInstruction(CilOpCodes.Ldloc, tVar);
        body.Instructions.Add(CilOpCodes.Ldloc, tVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_0);
        body.Instructions.Add(CilOpCodes.Bge, afterNeg.CreateLabel());
        body.Instructions.Add(CilOpCodes.Ldloc, tVar);
        body.Instructions.Add(CilOpCodes.Neg);
        body.Instructions.Add(CilOpCodes.Ldc_I4_5);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Stloc, tVar);

        body.Instructions.Add(afterNeg);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0xFF);
        body.Instructions.Add(CilOpCodes.And);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Ldc_I4_1);
        body.Instructions.Add(CilOpCodes.Shr);
        body.Instructions.Add(CilOpCodes.Sub);
        body.Instructions.Add(CilOpCodes.Ret);

        method.CilMethodBody = body;
        return (module, method);
    }

    private static (ModuleDefinition Module, MethodDefinition Method) BuildDynamicFallthroughCffMethod() {
        var module = CreateFreshNet8Module("DynamicFallthroughCff");
        var importer = module.DefaultImporter;
        var int32 = module.CorLibTypeFactory.Int32;

        var targetType = new TypeDefinition("AdversarialFixture", "DynamicFallthroughTarget",
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(targetType);

        var method = new MethodDefinition("Compute",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(int32, [int32, int32]));
        targetType.Methods.Add(method);

        var body = new CilMethodBody { InitializeLocals = true };
        var stateVar = new CilLocalVariable(int32);
        var accVar = new CilLocalVariable(int32);
        body.LocalVariables.Add(stateVar);
        body.LocalVariables.Add(accVar);

        var dispatcherStart = new CilInstruction(CilOpCodes.Ldloc, stateVar);
        var case0 = new CilInstruction(CilOpCodes.Nop);
        var case1 = new CilInstruction(CilOpCodes.Nop);
        var case2 = new CilInstruction(CilOpCodes.Nop);

        // Dynamic entry: state = a & 1; falls through directly into dispatcherStart!
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Ldc_I4_1);
        body.Instructions.Add(CilOpCodes.And);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);

        // Dispatcher: ldloc state; switch (case0, case1, case2)
        body.Instructions.Add(dispatcherStart);
        body.Instructions.Add(CilOpCodes.Switch, new List<ICilLabel> {
            case0.CreateLabel(), case1.CreateLabel(), case2.CreateLabel()
        });
        body.Instructions.Add(CilOpCodes.Ldc_I4_M1);
        body.Instructions.Add(CilOpCodes.Ret);

        // Case 0: acc = a + b; state = 2; br dispatcherStart
        body.Instructions.Add(case0);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_2);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcherStart.CreateLabel());

        // Case 1: acc = a - b; state = 2; br dispatcherStart
        body.Instructions.Add(case1);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Sub);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_2);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcherStart.CreateLabel());

        // Case 2: return acc * 3
        body.Instructions.Add(case2);
        body.Instructions.Add(CilOpCodes.Ldloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_3);
        body.Instructions.Add(CilOpCodes.Mul);
        body.Instructions.Add(CilOpCodes.Ret);

        method.CilMethodBody = body;
        return (module, method);
    }

    private static (TypeDefinition DelType, MethodDefinition DelCtor) CreateDelegateType(
        TypeDefinition vmType, ReferenceImporter importer, CorLibTypeFactory corlib) {
        var delType = new TypeDefinition("", "VmHandler",
            TypeAttributes.NestedPublic | TypeAttributes.Sealed | TypeAttributes.Class,
            importer.ImportType(typeof(MulticastDelegate)));
        vmType.NestedTypes.Add(delType);

        var delCtor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(corlib.Void, [corlib.Object, corlib.IntPtr])) {
            ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed
        };
        delType.Methods.Add(delCtor);
        return (delType, delCtor);
    }

    private static (FieldDefinition Field, IMethodDescriptor DictCtor, IMethodDescriptor DictAdd) CreateHandlerDictionary(
        TypeDefinition vmType, TypeDefinition delType, ReferenceImporter importer, CorLibTypeFactory corlib) {
        var dictOpen = importer.ImportType(typeof(Dictionary<,>));
        var dictSig = new GenericInstanceTypeSignature(dictOpen, isValueType: false, [corlib.UInt32, delType.ToTypeSignature()]);
        var field = new FieldDefinition("dictionary_0", FieldAttributes.Private, new FieldSignature(dictSig));
        vmType.Fields.Add(field);

        var dictTypeSpec = new TypeSpecification(dictSig);
        var dictCtor = new MemberReference(dictTypeSpec, ".ctor", MethodSignature.CreateInstance(corlib.Void));
        var dictAdd = new MemberReference(dictTypeSpec, "Add",
            MethodSignature.CreateInstance(corlib.Void, [
                new GenericParameterSignature(GenericParameterType.Type, 0),
                new GenericParameterSignature(GenericParameterType.Type, 1)
            ]));
        return (field, dictCtor, dictAdd);
    }

    private static (ModuleDefinition Module, List<string> ExpectedHandlerNames) BuildReflectionMetadataTokenVmModule() {
        var module = CreateFreshNet8Module("ReflectionTokenVm");
        var importer = module.DefaultImporter;
        var corlib = module.CorLibTypeFactory;

        var vmType = new TypeDefinition("AdversarialVm", "GClass105", TypeAttributes.Public | TypeAttributes.Class,
            importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(vmType);

        // Open instance delegate: public delegate void VmHandler(GClass105 instance);
        var delType = new TypeDefinition("", "VmHandler",
            TypeAttributes.NestedPublic | TypeAttributes.Sealed | TypeAttributes.Class,
            importer.ImportType(typeof(MulticastDelegate)));
        vmType.NestedTypes.Add(delType);

        var delCtor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(corlib.Void, [corlib.Object, corlib.IntPtr])) {
            ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed
        };
        var delInvoke = new MethodDefinition("Invoke",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.NewSlot | MethodAttributes.Virtual,
            MethodSignature.CreateInstance(corlib.Void, [vmType.ToTypeSignature()])) {
            ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed
        };
        delType.Methods.Add(delCtor);
        delType.Methods.Add(delInvoke);

        // Static Dictionary<uint, VmHandler> dictionary_0
        var dictOpen = importer.ImportType(typeof(Dictionary<,>));
        var dictSig = new GenericInstanceTypeSignature(dictOpen, isValueType: false, [corlib.UInt32, delType.ToTypeSignature()]);
        var dictField = new FieldDefinition("dictionary_0", FieldAttributes.Private | FieldAttributes.Static, new FieldSignature(dictSig));
        vmType.Fields.Add(dictField);

        var dictTypeSpec = new TypeSpecification(dictSig);
        var dictCtor = new MemberReference(dictTypeSpec, ".ctor", MethodSignature.CreateInstance(corlib.Void));
        var dictSetItem = new MemberReference(dictTypeSpec, "set_Item",
            MethodSignature.CreateInstance(corlib.Void, [
                new GenericParameterSignature(GenericParameterType.Type, 0),
                new GenericParameterSignature(GenericParameterType.Type, 1)
            ]));

        // Add 6 private instance handler methods matching VmHandler (void ())
        var expectedHandlerNames = new List<string>();
        for (int i = 0; i < 6; i++) {
            string name = $"method_{i}";
            var hm = new MethodDefinition(name, MethodAttributes.Private | MethodAttributes.HideBySig,
                MethodSignature.CreateInstance(corlib.Void));
            var hb = new CilMethodBody();
            hb.Instructions.Add(CilOpCodes.Ret);
            hm.CilMethodBody = hb;
            vmType.Methods.Add(hm);
            expectedHandlerNames.Add(name);
        }

        // Add non-matching private instance helper methods that Delegate.CreateDelegate(..., false) MUST skip
        var nonMatchingHelper1 = new MethodDefinition("helper_read", MethodAttributes.Private | MethodAttributes.HideBySig,
            MethodSignature.CreateInstance(corlib.Int32));
        var nh1 = new CilMethodBody();
        nh1.Instructions.Add(CilOpCodes.Ldc_I4_0);
        nh1.Instructions.Add(CilOpCodes.Ret);
        nonMatchingHelper1.CilMethodBody = nh1;
        vmType.Methods.Add(nonMatchingHelper1);

        var nonMatchingHelper2 = new MethodDefinition("helper_push", MethodAttributes.Private | MethodAttributes.HideBySig,
            MethodSignature.CreateInstance(corlib.Void, [corlib.Int32]));
        var nh2 = new CilMethodBody();
        nh2.Instructions.Add(CilOpCodes.Ret);
        nonMatchingHelper2.CilMethodBody = nh2;
        vmType.Methods.Add(nonMatchingHelper2);

        // Public VM entry method so DiscoverVm recognizes GClass105 as a VM type
        var entry = new MethodDefinition("Execute_0", MethodAttributes.Public | MethodAttributes.HideBySig,
            MethodSignature.CreateInstance(corlib.Object, [corlib.Object.MakeSzArrayType(), corlib.Int32]));
        var eb = new CilMethodBody();
        eb.Instructions.Add(CilOpCodes.Ldnull);
        eb.Instructions.Add(CilOpCodes.Ret);
        entry.CilMethodBody = eb;
        vmType.Methods.Add(entry);

        // GClass105::.cctor mirroring reflection MetadataToken registration loop:
        //   dictionary_0 = new Dictionary<uint, VmHandler>();
        //   MethodInfo[] methods = typeof(GClass105).GetMethods(BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.NonPublic);
        //   for (int i = 0; i < methods.Length; i++) {
        //       Delegate del = Delegate.CreateDelegate(typeof(VmHandler), methods[i], false);
        //       if (del != null)
        //           dictionary_0[(uint)methods[i].MetadataToken] = (VmHandler)del;
        //   }
        var typeGetFromHandle = importer.ImportMethod(typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle), [typeof(RuntimeTypeHandle)])!);
        var typeGetMethods = importer.ImportMethod(typeof(Type).GetMethod(nameof(Type.GetMethods), [typeof(BindingFlags)])!);
        var delCreate = importer.ImportMethod(typeof(Delegate).GetMethod(nameof(Delegate.CreateDelegate), [typeof(Type), typeof(MethodInfo), typeof(bool)])!);
        var getMetadataToken = importer.ImportMethod(typeof(MemberInfo).GetProperty(nameof(MemberInfo.MetadataToken))!.GetMethod!);
        var methodInfoArrSig = importer.ImportTypeSignature(typeof(MethodInfo[]));
        var methodInfoSig = importer.ImportTypeSignature(typeof(MethodInfo));
        var delegateSig = importer.ImportTypeSignature(typeof(Delegate));

        var cctor = new MethodDefinition(".cctor",
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateStatic(corlib.Void));
        vmType.Methods.Add(cctor);

        var cb = new CilMethodBody { InitializeLocals = true };
        var methodsLoc = new CilLocalVariable(methodInfoArrSig);
        var idxLoc = new CilLocalVariable(corlib.Int32);
        var curMiLoc = new CilLocalVariable(methodInfoSig);
        var delLoc = new CilLocalVariable(delegateSig);
        cb.LocalVariables.Add(methodsLoc);
        cb.LocalVariables.Add(idxLoc);
        cb.LocalVariables.Add(curMiLoc);
        cb.LocalVariables.Add(delLoc);

        var loopCheck = new CilInstruction(CilOpCodes.Ldloc, idxLoc);
        var loopBody = new CilInstruction(CilOpCodes.Ldloc, methodsLoc);
        var loopNext = new CilInstruction(CilOpCodes.Ldloc, idxLoc);

        cb.Instructions.Add(CilOpCodes.Newobj, dictCtor);
        cb.Instructions.Add(CilOpCodes.Stsfld, dictField);

        cb.Instructions.Add(CilOpCodes.Ldtoken, vmType);
        cb.Instructions.Add(CilOpCodes.Call, typeGetFromHandle);
        cb.Instructions.Add(CilOpCodes.Ldc_I4, (int)(BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.NonPublic));
        cb.Instructions.Add(CilOpCodes.Callvirt, typeGetMethods);
        cb.Instructions.Add(CilOpCodes.Stloc, methodsLoc);

        cb.Instructions.Add(CilOpCodes.Ldc_I4_0);
        cb.Instructions.Add(CilOpCodes.Stloc, idxLoc);
        cb.Instructions.Add(CilOpCodes.Br, loopCheck.CreateLabel());

        // Loop body
        cb.Instructions.Add(loopBody);
        cb.Instructions.Add(CilOpCodes.Ldloc, idxLoc);
        cb.Instructions.Add(CilOpCodes.Ldelem_Ref);
        cb.Instructions.Add(CilOpCodes.Stloc, curMiLoc);

        cb.Instructions.Add(CilOpCodes.Ldtoken, delType);
        cb.Instructions.Add(CilOpCodes.Call, typeGetFromHandle);
        cb.Instructions.Add(CilOpCodes.Ldloc, curMiLoc);
        cb.Instructions.Add(CilOpCodes.Ldc_I4_0);
        cb.Instructions.Add(CilOpCodes.Call, delCreate);
        cb.Instructions.Add(CilOpCodes.Stloc, delLoc);

        cb.Instructions.Add(CilOpCodes.Ldloc, delLoc);
        cb.Instructions.Add(CilOpCodes.Brfalse, loopNext.CreateLabel());

        cb.Instructions.Add(CilOpCodes.Ldsfld, dictField);
        cb.Instructions.Add(CilOpCodes.Ldloc, curMiLoc);
        cb.Instructions.Add(CilOpCodes.Callvirt, getMetadataToken);
        cb.Instructions.Add(CilOpCodes.Ldloc, delLoc);
        cb.Instructions.Add(CilOpCodes.Castclass, delType);
        cb.Instructions.Add(CilOpCodes.Callvirt, dictSetItem);

        // i++
        cb.Instructions.Add(loopNext);
        cb.Instructions.Add(CilOpCodes.Ldc_I4_1);
        cb.Instructions.Add(CilOpCodes.Add);
        cb.Instructions.Add(CilOpCodes.Stloc, idxLoc);

        // i < methods.Length
        cb.Instructions.Add(loopCheck);
        cb.Instructions.Add(CilOpCodes.Ldloc, methodsLoc);
        cb.Instructions.Add(CilOpCodes.Ldlen);
        cb.Instructions.Add(CilOpCodes.Conv_I4);
        cb.Instructions.Add(CilOpCodes.Blt, loopBody.CreateLabel());

        cb.Instructions.Add(CilOpCodes.Ret);
        cctor.CilMethodBody = cb;

        return (module, expectedHandlerNames);
    }

    private static void VerifyTier2DifferentialEquivalence(string devirtPath) {
        var alc = new CollectibleContext();
        try {
            var asm = alc.LoadFromAssemblyPath(devirtPath);
            var targetType = asm.GetType("SyntheticFixture.VirtualizedTargets", throwOnError: true)!;
            var rng = new Random(20261125);

            var addSubMul = targetType.GetMethod(nameof(ReferenceSuite.AddSubMul))!;
            for (int i = 0; i < 30; i++) {
                int a = rng.Next(-10_000, 10_000), b = rng.Next(-10_000, 10_000);
                Assert.Equal(ReferenceSuite.AddSubMul(a, b), (int)addSubMul.Invoke(null, [a, b])!);
            }

            var xorShift = targetType.GetMethod(nameof(ReferenceSuite.XorShiftMix))!;
            for (int i = 0; i < 30; i++) {
                int x = rng.Next(-100_000, 100_000), y = rng.Next(-100_000, 100_000);
                Assert.Equal(ReferenceSuite.XorShiftMix(x, y), (int)xorShift.Invoke(null, [x, y])!);
            }

            var clamp = targetType.GetMethod(nameof(ReferenceSuite.Clamp))!;
            for (int i = 0; i < 20; i++) {
                int min = rng.Next(-500, 500), max = min + rng.Next(0, 500), v = rng.Next(-1000, 1000);
                Assert.Equal(ReferenceSuite.Clamp(v, min, max), (int)clamp.Invoke(null, [v, min, max])!);
            }

            var sumRange = targetType.GetMethod(nameof(ReferenceSuite.SumRange))!;
            foreach (int n in new[] { -5, 0, 1, 10, 50 })
                Assert.Equal(ReferenceSuite.SumRange(n), (int)sumRange.Invoke(null, [n])!);

            var gcd = targetType.GetMethod(nameof(ReferenceSuite.Gcd))!;
            foreach (var (a, b) in new[] { (0, 0), (48, 18), (-48, 18), (1071, 462), (17, 13) })
                Assert.Equal(ReferenceSuite.Gcd(a, b), (int)gcd.Invoke(null, [a, b])!);

            var classify = targetType.GetMethod(nameof(ReferenceSuite.ClassifyScore))!;
            foreach (int s in new[] { -1, 0, 49, 50, 79, 80, 100 })
                Assert.Equal(ReferenceSuite.ClassifyScore(s), (int)classify.Invoke(null, [s])!);
        }
        finally {
            alc.Unload();
        }
    }

    private static string CreateTempDir(string tag) {
        string dir = Path.Combine(Path.GetTempPath(), "de4vmp-v2-adv", $"{tag}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void SafeDeleteDir(string dir) {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }
}
