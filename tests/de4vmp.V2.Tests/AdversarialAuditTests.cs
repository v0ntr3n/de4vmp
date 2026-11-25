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
    // 1. Obfuscated / Renamed VM Helper Methods
    // =========================================================================

    [Fact]
    public void RenamedVmHelpers_StructuralHandlersFailClosedToUnknown() {
        string workDir = CreateTempDir("renamed-helpers");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier2.dll");
            string obfPath = Path.Combine(workDir, "Virt_Tier2_RenamedHelpers.dll");

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

            // All 33 handlers are still discovered via bounded emulation of VmRuntime..ctor
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersDiscovered);

            int expectedProbed = truth.OpcodeMap.Values.Count(op => PureProbedOps.Contains(op));
            int expectedStructural = truth.OpcodeMap.Count - expectedProbed;

            // Pure arithmetic/comparison handlers still classify via behavioral I/O probing on H_XX_Core
            Assert.Equal(expectedProbed, metrics.HandlersClassified);

            // ALL structural handlers fail closed to SemanticOp.Unknown because HandlerSemanticClassifier
            // hardcodes English helper names ("ReadI4", "Push", "Pop", "Jump", "Halt", etc.)
            Assert.Equal(expectedStructural, metrics.UnknownHandlers);

            foreach (var (key, expectedOp) in truth.OpcodeMap) {
                Assert.True(metrics.Handlers.TryGetValue(key, out var resolved));
                if (PureProbedOps.Contains(expectedOp)) {
                    Assert.Equal(expectedOp, resolved!.SemanticOp);
                }
                else {
                    Assert.Equal(SemanticOp.Unknown, resolved!.SemanticOp);
                }
            }

            // Call sites are still discovered, but 0 methods can be devirtualized (fail-closed)
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(0, metrics.MethodsDevirtualized);
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
    public void BoundedEmulator_CrossTypeHelperRegistration_SilentlySkipsAndCapturesZeroHandlers() {
        var (module, vmCtor) = BuildVmCtorWithCrossTypeHelperRegistration();
        var emulator = new BoundedCilEmulator();

        var snap = emulator.EmulateMethod(vmCtor);

        // BoundedCilEmulator only steps into callees on the SAME DeclaringType (line 449).
        // Calls to another type's helper are silently stubbed with 0, so CompletedNormally is true
        // while 0 handlers are captured!
        Assert.True(snap.CompletedNormally);
        Assert.Empty(snap.CapturedHandlers);
    }

    [Theory]
    [InlineData("Add", 0x0000_0001_0000_0010L, 0x0000_0002_0000_0020L, 0x0000_0003_0000_0030L)]
    [InlineData("Sub", 0x0000_0005_0000_0030L, 0x0000_0002_0000_0010L, 0x0000_0003_0000_0020L)]
    [InlineData("Xor", 0x0000_0003_0000_000FL, 0x0000_0001_0000_00F0L, 0x0000_0002_0000_00FFL)]
    public void BoundedEmulator_Int64Arithmetic_SilentlyTruncatesToInt32(string opName, long a, long b, long expectedTrueInt64) {
        CilOpCode opCode = opName switch {
            "Add" => CilOpCodes.Add,
            "Sub" => CilOpCodes.Sub,
            "Xor" => CilOpCodes.Xor,
            _ => throw new ArgumentOutOfRangeException(nameof(opName))
        };

        var method = BuildInt64BinaryOpMethod(opName, opCode, a, b);
        var emulator = new BoundedCilEmulator();

        var snap = emulator.EmulateMethod(method);

        // Emulator does NOT fail closed on 64-bit arithmetic; it completes normally
        Assert.True(snap.CompletedNormally);

        // Empirically proves BoundedCilEmulator truncates Int64 operands via ToI4() and returns Int32!
        int truncatedActual = Assert.IsType<int>(snap.ReturnValue);
        Assert.Equal(unchecked((int)expectedTrueInt64), truncatedActual);
        Assert.NotEqual(expectedTrueInt64, (long)truncatedActual);
    }

    // =========================================================================
    // 4. Computed Call-Site Offsets & Non-ManifestResource Bytecode
    // =========================================================================

    [Fact]
    public void ComputedCallSiteOffsets_MissedByFindVerifiedCallSites() {
        string workDir = CreateTempDir("computed-callsite");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier2.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier2_ComputedOffsets.dll");

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

            // Handlers are still 100% discovered and classified
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersDiscovered);
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersClassified);

            // FindVerifiedCallSites requires `insns[i - 1].IsLdcI4()`, so computed offsets yield 0 methods discovered!
            Assert.Equal(0, metrics.MethodsDiscovered);
            Assert.Equal(0, metrics.MethodsDevirtualized);
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void NonManifestResource_RenamedOrInCodeBytecode_FailsToExtractAndDevirtualize() {
        string workDir = CreateTempDir("non-manifest-bytecode");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier2.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier2_NoVmBytecodeResource.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic, virtPath);
            var module = ModuleDefinition.FromFile(virtPath);

            // Rename ManifestResource from hardcoded "VmBytecode" to an obfuscated name and clear FieldRva
            var res = module.Resources.First(r => r.Name == "VmBytecode");
            res.Name = "EncryptedBlob_9F3A";
            var vmType = module.TopLevelTypes.First(t => t.Name == "VmRuntime");
            var blobField = vmType.Fields.First(f => f.Name == "BytecodeBlob");
            blobField.FieldRva = null;
            blobField.Attributes &= ~FieldAttributes.HasFieldRva;

            module.Write(modPath);
            var reloaded = ModuleDefinition.FromFile(modPath);

            var devirt = new V2Devirtualizer();
            var diags = new List<string>();
            var discovery = devirt.DiscoverVm(reloaded, diags);

            // VM is discovered, but bytecode blob extraction returns empty array
            Assert.NotNull(discovery);
            Assert.Empty(discovery!.BytecodeBlob);

            var metrics = devirt.Devirtualize(reloaded);
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersClassified);
            Assert.Equal(0, metrics.MethodsDevirtualized);
            Assert.Contains(metrics.Diagnostics, d => d.Contains("invalid bytecode offset", StringComparison.OrdinalIgnoreCase));
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

    private static string CreateTempDir(string tag) {
        string dir = Path.Combine(Path.GetTempPath(), "de4vmp-v2-adv", $"{tag}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void SafeDeleteDir(string dir) {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }
}
