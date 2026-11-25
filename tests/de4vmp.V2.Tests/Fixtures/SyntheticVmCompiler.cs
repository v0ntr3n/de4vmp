using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;
using de4vmp.V2.Models;

namespace de4vmp.V2.Tests.Fixtures;

public enum SyntheticTier {
    Tier1_Clean8BitTable = 1,
    Tier2_32BitDictEncryptedPolymorphic = 2,
    Tier3_CffAndOpaquePredicates = 3,
    Tier4_MultiEntryObjectsAndEh = 4
}

public sealed record GroundTruth(
    SyntheticTier Tier,
    IReadOnlyDictionary<uint, SemanticOp> OpcodeMap,
    IReadOnlyList<string> VirtualizedMethods,
    string VirtualizedAssemblyPath);

/// <summary>
/// Self-authored synthetic .NET 8.0 VM compiler generating Tiers 1-4 fixtures + GroundTruth.
/// Emits real ECMA-335 PE assemblies with AsmResolver 6.0.0.
/// </summary>
public sealed class SyntheticVmCompiler {
    private static readonly SemanticOp[] BaseOps = [
        SemanticOp.Nop, SemanticOp.LdcI4, SemanticOp.LdArg, SemanticOp.LdLoc, SemanticOp.StLoc,
        SemanticOp.Add, SemanticOp.Sub, SemanticOp.Mul, SemanticOp.Div, SemanticOp.Rem,
        SemanticOp.Xor, SemanticOp.And, SemanticOp.Or, SemanticOp.Shl, SemanticOp.Shr, SemanticOp.Neg,
        SemanticOp.Ceq, SemanticOp.Clt, SemanticOp.Cgt,
        SemanticOp.Br, SemanticOp.BrTrue, SemanticOp.BrFalse, SemanticOp.Ret,
        SemanticOp.NewObj, SemanticOp.LdFld, SemanticOp.StFld, SemanticOp.Call, SemanticOp.CallVirt,
        SemanticOp.LdElemI4, SemanticOp.StElemI4, SemanticOp.LdLen, SemanticOp.Leave, SemanticOp.EndFinally
    ];

    public GroundTruth Generate(SyntheticTier tier, string outputDllPath) {
        bool is32Bit = tier >= SyntheticTier.Tier2_32BitDictEncryptedPolymorphic;
        bool useEncryption = tier >= SyntheticTier.Tier2_32BitDictEncryptedPolymorphic;
        bool usePolymorphic = tier >= SyntheticTier.Tier2_32BitDictEncryptedPolymorphic;
        bool useCff = tier >= SyntheticTier.Tier3_CffAndOpaquePredicates;
        bool useMultiEntry = tier >= SyntheticTier.Tier4_MultiEntryObjectsAndEh;

        uint keySeed = useEncryption ? 0x5A3C19F7u : 0u;
        uint keyStep = useEncryption ? 0x1F3D5B79u : 0u;

        // Build fresh .NET 8.0 module referencing System.Runtime + ReferenceSuite's assembly (for ReferenceCounter)
        var refModule = ModuleDefinition.FromFile(typeof(ReferenceSuite).Assembly.Location);
        var module = new ModuleDefinition($"SyntheticFixture_{tier}.dll", refModule.CorLibTypeFactory.CorLibScope as AssemblyReference);
        var assembly = new AssemblyDefinition($"SyntheticFixture_{tier}", new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);

        var importer = module.DefaultImporter;
        var corlib = module.CorLibTypeFactory;

        var objType = corlib.Object;
        var voidType = corlib.Void;
        var int32Type = corlib.Int32;
        var uint32Type = corlib.UInt32;
        var byteArrayType = corlib.Byte.MakeSzArrayType();
        var intArrayType = int32Type.MakeSzArrayType();
        var objArrayType = objType.MakeSzArrayType();

        // Import BCL types
        var objectCtor = importer.ImportMethod(typeof(object).GetConstructor(Type.EmptyTypes)!);
        var multicastDelegateRef = importer.ImportType(typeof(MulticastDelegate));
        var intPtrType = corlib.IntPtr;
        var divideByZeroRef = importer.ImportType(typeof(DivideByZeroException));

        // Import ReferenceCounter (type, .ctor(int), Value field, AddAndGet(int) method)
        var counterTypeRef = importer.ImportType(typeof(ReferenceCounter));
        var counterCtorRef = importer.ImportMethod(typeof(ReferenceCounter).GetConstructor([typeof(int)])!);
        var counterValueFieldRef = importer.ImportField(typeof(ReferenceCounter).GetField(nameof(ReferenceCounter.Value))!);
        var counterAddAndGetRef = importer.ImportMethod(typeof(ReferenceCounter).GetMethod(nameof(ReferenceCounter.AddAndGet))!);

        // Create VM runtime type
        var vmType = new TypeDefinition("SyntheticVm", "VmRuntime", TypeAttributes.Public | TypeAttributes.Class, importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(vmType);

        // Nested delegate: public delegate void VmHandler();
        var delType = new TypeDefinition("", "VmHandler",
            TypeAttributes.NestedPublic | TypeAttributes.Sealed | TypeAttributes.Class,
            multicastDelegateRef);
        vmType.NestedTypes.Add(delType);

        var delCtor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(voidType, [objType, intPtrType])) {
            ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed
        };
        var delInvoke = new MethodDefinition("Invoke",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.NewSlot | MethodAttributes.Virtual,
            MethodSignature.CreateInstance(voidType)) {
            ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed
        };
        delType.Methods.Add(delCtor);
        delType.Methods.Add(delInvoke);

        // Build opcode key map
        var opcodeMap = new Dictionary<uint, SemanticOp>();
        var opToKey = new Dictionary<SemanticOp, uint>();
        for (uint i = 0; i < BaseOps.Length; i++) {
            uint key = is32Bit ? unchecked(0xA511E9B3u ^ (i * 0x9E3779B9u)) : (i + 1u);
            opcodeMap[key] = BaseOps[i];
            opToKey[BaseOps[i]] = key;
        }

        // VM runtime state fields (used by helpers with real, name-invariant CIL semantics)
        var boolType = corlib.Boolean;
        var stackOpen = importer.ImportType(typeof(Stack<>));
        var intStackSig = new GenericInstanceTypeSignature(stackOpen, isValueType: false, [int32Type]);
        var intStackTypeSpec = new TypeSpecification(intStackSig);
        var intStackPop = new MemberReference(intStackTypeSpec, "Pop",
            MethodSignature.CreateInstance(new GenericParameterSignature(GenericParameterType.Type, 0)));

        var codeField = new FieldDefinition("_code", FieldAttributes.Private, new FieldSignature(byteArrayType));
        var ipField = new FieldDefinition("_ip", FieldAttributes.Private, new FieldSignature(int32Type));
        var spField = new FieldDefinition("_sp", FieldAttributes.Private, new FieldSignature(int32Type));
        var stackField = new FieldDefinition("_stack", FieldAttributes.Private, new FieldSignature(intArrayType));
        var argsField = new FieldDefinition("_args", FieldAttributes.Private, new FieldSignature(objArrayType));
        var localsField = new FieldDefinition("_locals", FieldAttributes.Private, new FieldSignature(intArrayType));
        var haltedField = new FieldDefinition("_halted", FieldAttributes.Private, new FieldSignature(boolType));
        var ehStackField = new FieldDefinition("_ehStack", FieldAttributes.Private, new FieldSignature(intStackSig));

        vmType.Fields.Add(codeField);
        vmType.Fields.Add(ipField);
        vmType.Fields.Add(spField);
        vmType.Fields.Add(stackField);
        vmType.Fields.Add(argsField);
        vmType.Fields.Add(localsField);
        vmType.Fields.Add(haltedField);
        vmType.Fields.Add(ehStackField);

        var bitConvToInt32 = importer.ImportMethod(typeof(BitConverter).GetMethod(nameof(BitConverter.ToInt32), [typeof(byte[]), typeof(int)])!);
        var activatorCreate = importer.ImportMethod(typeof(Activator).GetMethod(nameof(Activator.CreateInstance), [typeof(Type)])!);
        var fieldInfoGetValue = importer.ImportMethod(typeof(System.Reflection.FieldInfo).GetMethod(nameof(System.Reflection.FieldInfo.GetValue), [typeof(object)])!);
        var fieldInfoSetValue = importer.ImportMethod(typeof(System.Reflection.FieldInfo).GetMethod(nameof(System.Reflection.FieldInfo.SetValue), [typeof(object), typeof(object)])!);
        var methodBaseInvoke = importer.ImportMethod(typeof(System.Reflection.MethodBase).GetMethod(nameof(System.Reflection.MethodBase.Invoke), [typeof(object), typeof(object[])])!);
        var methodBaseGetIsVirtual = importer.ImportMethod(typeof(System.Reflection.MethodBase).GetProperty(nameof(System.Reflection.MethodBase.IsVirtual))!.GetMethod!);
        var methodBaseTypeSig = importer.ImportTypeSignature(typeof(System.Reflection.MethodBase));

        // VM helper methods with real, distinguishable minimal CIL semantics (completely invariant to renaming)
        var helperNames = new[] {
            "ReadI4", "Push", "Pop", "GetArg", "GetLoc", "SetLoc",
            "Jump", "JumpIfTrue", "JumpIfFalse", "Halt",
            "VmNewObj", "VmLdFld", "VmStFld", "VmCall", "VmCallVirt",
            "VmLdElemI4", "VmStElemI4", "VmLdLen", "VmLeave", "VmEndFinally", "Op_Nop"
        };
        var helpers = new Dictionary<string, MethodDefinition>();
        foreach (string hName in helperNames) {
            var sig = hName switch {
                "ReadI4" or "Pop" or "GetArg" or "GetLoc" => MethodSignature.CreateInstance(int32Type),
                "Push" or "SetLoc" => MethodSignature.CreateInstance(voidType, [int32Type]),
                _ => MethodSignature.CreateInstance(voidType)
            };
            var hm = new MethodDefinition(hName, MethodAttributes.Private, sig);
            vmType.Methods.Add(hm);
            helpers[hName] = hm;
        }

        // Populate each helper's real CIL body
        {
            // Op_Nop: empty no-op
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["Op_Nop"].CilMethodBody = b;
        }
        {
            // ReadI4: int val = BitConverter.ToInt32(_code, _ip); _ip += 4; return val;
            var b = new CilMethodBody { InitializeLocals = true };
            var valLoc = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(valLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, codeField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Call, bitConvToInt32);
            b.Instructions.Add(CilOpCodes.Stloc, valLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_4);
            b.Instructions.Add(CilOpCodes.Add);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldloc, valLoc);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["ReadI4"].CilMethodBody = b;
        }
        {
            // Push(int v): _stack[_sp] = v; _sp += 1;
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, stackField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldarg_1);
            b.Instructions.Add(CilOpCodes.Stelem_I4);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1);
            b.Instructions.Add(CilOpCodes.Add);
            b.Instructions.Add(CilOpCodes.Stfld, spField);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["Push"].CilMethodBody = b;
        }
        {
            // Pop(): _sp -= 1; return _stack[_sp];
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1);
            b.Instructions.Add(CilOpCodes.Sub);
            b.Instructions.Add(CilOpCodes.Stfld, spField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, stackField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldelem_I4);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["Pop"].CilMethodBody = b;
        }
        {
            // GetArg(): return (int)_args[ReadI4()];
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, argsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
            b.Instructions.Add(CilOpCodes.Ldelem_Ref);
            b.Instructions.Add(CilOpCodes.Unbox_Any, int32Type.ToTypeDefOrRef());
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["GetArg"].CilMethodBody = b;
        }
        {
            // GetLoc(): return _locals[ReadI4()];
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, localsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
            b.Instructions.Add(CilOpCodes.Ldelem_I4);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["GetLoc"].CilMethodBody = b;
        }
        {
            // SetLoc(int v): _locals[ReadI4()] = v;
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, localsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
            b.Instructions.Add(CilOpCodes.Ldarg_1);
            b.Instructions.Add(CilOpCodes.Stelem_I4);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["SetLoc"].CilMethodBody = b;
        }
        {
            // Jump(): _ip = ReadI4();
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["Jump"].CilMethodBody = b;
        }
        {
            // JumpIfTrue(): int target = ReadI4(); if (Pop() != 0) _ip = target;
            var b = new CilMethodBody { InitializeLocals = true };
            var targetLoc = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(targetLoc);
            var done = new CilInstruction(CilOpCodes.Ret);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
            b.Instructions.Add(CilOpCodes.Stloc, targetLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Brfalse_S, done.CreateLabel());
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldloc, targetLoc);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(done);
            helpers["JumpIfTrue"].CilMethodBody = b;
        }
        {
            // JumpIfFalse(): int target = ReadI4(); if (Pop() == 0) _ip = target;
            var b = new CilMethodBody { InitializeLocals = true };
            var targetLoc = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(targetLoc);
            var done = new CilInstruction(CilOpCodes.Ret);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
            b.Instructions.Add(CilOpCodes.Stloc, targetLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Brtrue_S, done.CreateLabel());
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldloc, targetLoc);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(done);
            helpers["JumpIfFalse"].CilMethodBody = b;
        }
        {
            // Halt(): _halted = true;
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1);
            b.Instructions.Add(CilOpCodes.Stfld, haltedField);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["Halt"].CilMethodBody = b;
        }
        {
            // VmNewObj(): Activator.CreateInstance(null);
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Call, activatorCreate);
            b.Instructions.Add(CilOpCodes.Pop);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmNewObj"].CilMethodBody = b;
        }
        {
            // VmLdFld(): FieldInfo.GetValue(null);
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Callvirt, fieldInfoGetValue);
            b.Instructions.Add(CilOpCodes.Pop);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmLdFld"].CilMethodBody = b;
        }
        {
            // VmStFld(): FieldInfo.SetValue(null, null);
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Callvirt, fieldInfoSetValue);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmStFld"].CilMethodBody = b;
        }
        {
            // VmCall(): MethodBase.Invoke(null, null);
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Callvirt, methodBaseInvoke);
            b.Instructions.Add(CilOpCodes.Pop);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmCall"].CilMethodBody = b;
        }
        {
            // VmCallVirt(): checks MethodBase.IsVirtual + MethodBase.Invoke(null, null);
            var b = new CilMethodBody { InitializeLocals = true };
            var mbLoc = new CilLocalVariable(methodBaseTypeSig);
            b.LocalVariables.Add(mbLoc);
            b.Instructions.Add(CilOpCodes.Ldloc, mbLoc);
            b.Instructions.Add(CilOpCodes.Callvirt, methodBaseGetIsVirtual);
            b.Instructions.Add(CilOpCodes.Pop);
            b.Instructions.Add(CilOpCodes.Ldloc, mbLoc);
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Ldnull);
            b.Instructions.Add(CilOpCodes.Callvirt, methodBaseInvoke);
            b.Instructions.Add(CilOpCodes.Pop);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmCallVirt"].CilMethodBody = b;
        }
        {
            // VmLdElemI4(): int idx = Pop(); Push(arr[idx]);
            var b = new CilMethodBody { InitializeLocals = true };
            var arrLoc = new CilLocalVariable(intArrayType);
            var idxLoc = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(arrLoc);
            b.LocalVariables.Add(idxLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Stloc, idxLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldloc, arrLoc);
            b.Instructions.Add(CilOpCodes.Ldloc, idxLoc);
            b.Instructions.Add(CilOpCodes.Ldelem_I4);
            b.Instructions.Add(CilOpCodes.Call, helpers["Push"]);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmLdElemI4"].CilMethodBody = b;
        }
        {
            // VmStElemI4(): int val = Pop(); int idx = Pop(); arr[idx] = val;
            var b = new CilMethodBody { InitializeLocals = true };
            var arrLoc = new CilLocalVariable(intArrayType);
            var valLoc = new CilLocalVariable(int32Type);
            var idxLoc = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(arrLoc);
            b.LocalVariables.Add(valLoc);
            b.LocalVariables.Add(idxLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Stloc, valLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Stloc, idxLoc);
            b.Instructions.Add(CilOpCodes.Ldloc, arrLoc);
            b.Instructions.Add(CilOpCodes.Ldloc, idxLoc);
            b.Instructions.Add(CilOpCodes.Ldloc, valLoc);
            b.Instructions.Add(CilOpCodes.Stelem_I4);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmStElemI4"].CilMethodBody = b;
        }
        {
            // VmLdLen(): Push(arr.Length);
            var b = new CilMethodBody { InitializeLocals = true };
            var arrLoc = new CilLocalVariable(intArrayType);
            b.LocalVariables.Add(arrLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldloc, arrLoc);
            b.Instructions.Add(CilOpCodes.Ldlen);
            b.Instructions.Add(CilOpCodes.Conv_I4);
            b.Instructions.Add(CilOpCodes.Call, helpers["Push"]);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmLdLen"].CilMethodBody = b;
        }
        {
            // VmLeave(): _sp = 0; _ip = ReadI4();
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldc_I4_0);
            b.Instructions.Add(CilOpCodes.Stfld, spField);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmLeave"].CilMethodBody = b;
        }
        {
            // VmEndFinally(): _ip = _ehStack.Pop();
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldfld, ehStackField);
            b.Instructions.Add(CilOpCodes.Callvirt, intStackPop);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(CilOpCodes.Ret);
            helpers["VmEndFinally"].CilMethodBody = b;
        }

        // Create handler methods for every SemanticOp
        var handlerMethods = new Dictionary<SemanticOp, MethodDefinition>();
        int hCounter = 0;
        foreach (var op in BaseOps) {
            var hm = EmitHandlerMethod(vmType, op, $"H_{hCounter++:D2}", helpers, usePolymorphic, useCff, int32Type, voidType);
            handlerMethods[op] = hm;
        }

        // VM storage field: either Dictionary<uint, VmHandler> or VmHandler[]
        FieldDefinition tableField;
        IMethodDescriptor? dictCtor = null;
        IMethodDescriptor? dictAdd = null;

        if (is32Bit) {
            var dictOpen = importer.ImportType(typeof(Dictionary<,>));
            var dictSig = new GenericInstanceTypeSignature(dictOpen, isValueType: false, [uint32Type, delType.ToTypeSignature()]);
            tableField = new FieldDefinition("dictionary_0", FieldAttributes.Private, new FieldSignature(dictSig));
            vmType.Fields.Add(tableField);

            var dictTypeSpec = new TypeSpecification(dictSig);
            dictCtor = new MemberReference(dictTypeSpec, ".ctor", MethodSignature.CreateInstance(voidType));
            dictAdd = new MemberReference(dictTypeSpec, "Add",
                MethodSignature.CreateInstance(voidType, [new GenericParameterSignature(GenericParameterType.Type, 0), new GenericParameterSignature(GenericParameterType.Type, 1)]));
        }
        else {
            tableField = new FieldDefinition("handlers_0", FieldAttributes.Private, new FieldSignature(delType.ToTypeSignature().MakeSzArrayType()));
            vmType.Fields.Add(tableField);
        }

        // Emit VM .ctor registering all handlers (with CFF + opaque predicates in Tier 3/4!)
        var vmCtor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(voidType));
        vmType.Methods.Add(vmCtor);
        EmitVmCtor(vmCtor, objectCtor, tableField, delType, delCtor, dictCtor, dictAdd, opToKey, handlerMethods, is32Bit, useCff, int32Type);

        // Emit VM entry method(s): Tier 1-3 -> 1 entry (object[], int); Tier 4 -> 3 entries (object, int)
        var entryMethods = new List<MethodDefinition>();
        int entryCount = useMultiEntry ? 3 : 1;
        for (int e = 0; e < entryCount; e++) {
            TypeSignature p0Type = useMultiEntry ? objType : objArrayType;
            var em = new MethodDefinition($"Execute_{e}", MethodAttributes.Public | MethodAttributes.HideBySig,
                MethodSignature.CreateInstance(objType, [p0Type, int32Type]));
            var eb = new CilMethodBody();
            eb.Instructions.Add(CilOpCodes.Ldnull);
            eb.Instructions.Add(CilOpCodes.Ret);
            em.CilMethodBody = eb;
            vmType.Methods.Add(em);
            entryMethods.Add(em);
        }

        // Build target type containing virtualized methods
        var targetType = new TypeDefinition("SyntheticFixture", "VirtualizedTargets", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed, importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(targetType);

        // Ensure member tokens for ReferenceCounter / DivideByZeroException exist in module before encoding bytecode!
        // We create a tiny metadata anchor method or write them via a helper so LookupMember resolves them cleanly.
        var bytecodeStream = new MemoryStream();
        var virtualizedNames = new List<string>();

        // Emit all target methods (stubs initially, then we serialize bytecode after tokens are assigned)
        var methodSpecs = BuildMethodSpecs(tier, module.RuntimeContext, corlib, int32Type, intArrayType, counterTypeRef, counterCtorRef, counterValueFieldRef, counterAddAndGetRef, divideByZeroRef);

        // First add all target methods to targetType so we can compute tokens
        var targetMethods = new List<(MethodDefinition Method, MethodSpec Spec)>();
        foreach (var spec in methodSpecs) {
            var m = new MethodDefinition(spec.Name, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, spec.Signature);
            targetType.Methods.Add(m);
            targetMethods.Add((m, spec));
            virtualizedNames.Add(spec.Name);
        }

        // Write a tiny anchor method referencing imported members so AsmResolver assigns stable tokens
        // Wait: tokens are assigned on write; to ensure exact metadata tokens match LookupMember after reload,
        // we first add a static field for the bytecode blob, do a two-pass write (pass 1 assigns tokens, pass 2 writes final blob).
        var anchor = new MethodDefinition("__MetadataAnchor", MethodAttributes.Private | MethodAttributes.Static, MethodSignature.CreateStatic(voidType));
        var ab = new CilMethodBody();
        ab.Instructions.Add(CilOpCodes.Ldtoken, counterTypeRef);
        ab.Instructions.Add(CilOpCodes.Pop);
        ab.Instructions.Add(CilOpCodes.Ldtoken, divideByZeroRef);
        ab.Instructions.Add(CilOpCodes.Pop);
        ab.Instructions.Add(CilOpCodes.Ldtoken, counterCtorRef);
        ab.Instructions.Add(CilOpCodes.Pop);
        ab.Instructions.Add(CilOpCodes.Ldtoken, counterValueFieldRef);
        ab.Instructions.Add(CilOpCodes.Pop);
        ab.Instructions.Add(CilOpCodes.Ldtoken, counterAddAndGetRef);
        ab.Instructions.Add(CilOpCodes.Pop);
        ab.Instructions.Add(CilOpCodes.Ret);
        anchor.CilMethodBody = ab;
        vmType.Methods.Add(anchor);

        // Static fields for encryption keys + bytecode blob
        if (useEncryption) {
            var seedField = new FieldDefinition("KeySeed", FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal, new FieldSignature(uint32Type)) {
                Constant = new Constant(ElementType.U4, new DataBlobSignature(BitConverter.GetBytes(keySeed)))
            };
            var stepField = new FieldDefinition("KeyStep", FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal, new FieldSignature(uint32Type)) {
                Constant = new Constant(ElementType.U4, new DataBlobSignature(BitConverter.GetBytes(keyStep)))
            };
            vmType.Fields.Add(seedField);
            vmType.Fields.Add(stepField);
        }

        var blobField = new FieldDefinition("BytecodeBlob", FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRva, new FieldSignature(byteArrayType));
        vmType.Fields.Add(blobField);

        // Placeholder stubs + dummy blob for Pass 1 (to obtain exact final MetadataTokens for imported members)
        foreach (var (m, _) in targetMethods) {
            EmitVmStub(m, vmCtor, entryMethods[0], 0, objType, int32Type);
        }
        blobField.FieldRva = new DataSegment(new byte[16]);

        string? dir = Path.GetDirectoryName(outputDllPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        module.Write(outputDllPath);

        // Reload module to read the exact assigned MetadataTokens for imported members
        var pass2Module = ModuleDefinition.FromFile(outputDllPath);
        var p2Vm = pass2Module.TopLevelTypes.First(t => t.Name == "VmRuntime");
        var p2Target = pass2Module.TopLevelTypes.First(t => t.Name == "VirtualizedTargets");
        var p2Anchor = p2Vm.Methods.First(m => m.Name == "__MetadataAnchor");
        var anchorTokens = p2Anchor.CilMethodBody!.Instructions
            .Where(i => i.OpCode.Code == CilCode.Ldtoken)
            .Select(i => ((IMetadataMember)i.Operand!).MetadataToken.ToInt32())
            .ToArray();

        int tokCounterType = anchorTokens[0];
        int tokDivByZero = anchorTokens[1];
        int tokCounterCtor = anchorTokens[2];
        int tokCounterValue = anchorTokens[3];
        int tokCounterAddAndGet = anchorTokens[4];

        var p2VmCtor = p2Vm.Methods.First(m => m.IsConstructor && !m.IsStatic);
        var p2Entries = p2Vm.Methods.Where(m => m.Name?.Value.StartsWith("Execute_") == true).ToList();

        // Encode bytecode for every method using exact tokens
        var rawBlob = new MemoryStream();
        var bw = new BinaryWriter(rawBlob);

        for (int idx = 0; idx < methodSpecs.Count; idx++) {
            var spec = methodSpecs[idx];
            int methodOffset = (int)rawBlob.Position;
            var ops = spec.BuildOps(tokCounterCtor, tokCounterValue, tokCounterAddAndGet, tokDivByZero);

            bw.Write(spec.LocalCount);
            bw.Write(ops.Instructions.Count);
            bw.Write(ops.EhClauses.Count);

            foreach (var (op, operand) in ops.Instructions) {
                uint key = opToKey[op];
                if (is32Bit) bw.Write(key);
                else bw.Write((byte)key);

                if (HasOperand(op))
                    bw.Write(operand);
            }

            foreach (var eh in ops.EhClauses) {
                bw.Write(eh.Kind);
                bw.Write(eh.TryStart);
                bw.Write(eh.TryEnd);
                bw.Write(eh.HandlerStart);
                bw.Write(eh.HandlerEnd);
                bw.Write(eh.CatchTypeToken);
            }

            // Rewrite target method stub with exact offset & rotating entry method (for Tier 4 multi-entry)
            var p2Method = p2Target.Methods.First(m => m.Name == spec.Name);
            var chosenEntry = p2Entries[idx % p2Entries.Count];
            EmitVmStub(p2Method, p2VmCtor, chosenEntry, methodOffset, pass2Module.CorLibTypeFactory.Object, pass2Module.CorLibTypeFactory.Int32);
        }

        byte[] plainBytes = rawBlob.ToArray();
        byte[] storedBytes = useEncryption ? EncryptBytecode(plainBytes, keySeed, keyStep) : plainBytes;

        pass2Module.Resources.Add(new ManifestResource("VmBytecode", ManifestResourceAttributes.Public, new DataSegment(storedBytes)));

        pass2Module.Write(outputDllPath);

        return new GroundTruth(tier, opcodeMap, virtualizedNames, outputDllPath);
    }

    private static MethodDefinition EmitHandlerMethod(
        TypeDefinition vmType,
        SemanticOp op,
        string name,
        Dictionary<string, MethodDefinition> helpers,
        bool polymorphic,
        bool cff,
        TypeSignature int32Type,
        TypeSignature voidType) {
        var m = new MethodDefinition(name, MethodAttributes.Private, MethodSignature.CreateInstance(voidType));
        var b = new CilMethodBody();

        // For arithmetic/bitwise/comparison ops, emit a pure (int, int) -> int or (int) -> int helper method
        // so polymorphic/mutated implementations are verified via behavioral I/O equivalence!
        bool isBinaryPure = op is SemanticOp.Add or SemanticOp.Sub or SemanticOp.Mul or SemanticOp.Div or SemanticOp.Rem
            or SemanticOp.Xor or SemanticOp.And or SemanticOp.Or or SemanticOp.Shl or SemanticOp.Shr
            or SemanticOp.Ceq or SemanticOp.Clt or SemanticOp.Cgt;

        if (isBinaryPure) {
            var helper = new MethodDefinition($"{name}_Core", MethodAttributes.Private,
                MethodSignature.CreateInstance(int32Type, [int32Type, int32Type]));
            var hb = new CilMethodBody();

            if (polymorphic && op == SemanticOp.Add) {
                // Polymorphic Add: a - (-b)
                hb.Instructions.Add(CilOpCodes.Ldarg_1);
                hb.Instructions.Add(CilOpCodes.Ldarg_2);
                hb.Instructions.Add(CilOpCodes.Neg);
                hb.Instructions.Add(CilOpCodes.Sub);
                hb.Instructions.Add(CilOpCodes.Ret);
            }
            else if (polymorphic && op == SemanticOp.Xor) {
                // Polymorphic Xor: (a | b) - (a & b)
                hb.Instructions.Add(CilOpCodes.Ldarg_1);
                hb.Instructions.Add(CilOpCodes.Ldarg_2);
                hb.Instructions.Add(CilOpCodes.Or);
                hb.Instructions.Add(CilOpCodes.Ldarg_1);
                hb.Instructions.Add(CilOpCodes.Ldarg_2);
                hb.Instructions.Add(CilOpCodes.And);
                hb.Instructions.Add(CilOpCodes.Sub);
                hb.Instructions.Add(CilOpCodes.Ret);
            }
            else {
                hb.Instructions.Add(CilOpCodes.Ldarg_1);
                hb.Instructions.Add(CilOpCodes.Ldarg_2);
                hb.Instructions.Add(op switch {
                    SemanticOp.Add => CilOpCodes.Add,
                    SemanticOp.Sub => CilOpCodes.Sub,
                    SemanticOp.Mul => CilOpCodes.Mul,
                    SemanticOp.Div => CilOpCodes.Div,
                    SemanticOp.Rem => CilOpCodes.Rem,
                    SemanticOp.Xor => CilOpCodes.Xor,
                    SemanticOp.And => CilOpCodes.And,
                    SemanticOp.Or => CilOpCodes.Or,
                    SemanticOp.Shl => CilOpCodes.Shl,
                    SemanticOp.Shr => CilOpCodes.Shr,
                    SemanticOp.Ceq => CilOpCodes.Ceq,
                    SemanticOp.Clt => CilOpCodes.Clt,
                    SemanticOp.Cgt => CilOpCodes.Cgt,
                    _ => CilOpCodes.Add
                });
                hb.Instructions.Add(CilOpCodes.Ret);
            }

            if (cff) WrapWithCffAndOpaquePredicate(hb, int32Type);
            helper.CilMethodBody = hb;
            vmType.Methods.Add(helper);

            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Call, helper);
            b.Instructions.Add(CilOpCodes.Pop);
            b.Instructions.Add(CilOpCodes.Ret);
        }
        else if (op == SemanticOp.Neg) {
            var helper = new MethodDefinition($"{name}_Core", MethodAttributes.Private,
                MethodSignature.CreateInstance(int32Type, [int32Type]));
            var hb = new CilMethodBody();
            if (polymorphic) {
                // Polymorphic Neg: (~a) + 1
                hb.Instructions.Add(CilOpCodes.Ldarg_1);
                hb.Instructions.Add(CilOpCodes.Not);
                hb.Instructions.Add(CilOpCodes.Ldc_I4_1);
                hb.Instructions.Add(CilOpCodes.Add);
                hb.Instructions.Add(CilOpCodes.Ret);
            }
            else {
                hb.Instructions.Add(CilOpCodes.Ldarg_1);
                hb.Instructions.Add(CilOpCodes.Neg);
                hb.Instructions.Add(CilOpCodes.Ret);
            }
            if (cff) WrapWithCffAndOpaquePredicate(hb, int32Type);
            helper.CilMethodBody = hb;
            vmType.Methods.Add(helper);

            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
            b.Instructions.Add(CilOpCodes.Call, helper);
            b.Instructions.Add(CilOpCodes.Pop);
            b.Instructions.Add(CilOpCodes.Ret);
        }
        else {
            // Semantic VM-state / managed-object handlers
            switch (op) {
                case SemanticOp.Nop:
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Call, helpers["Op_Nop"]);
                    break;
                case SemanticOp.LdcI4:
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Call, helpers["ReadI4"]);
                    b.Instructions.Add(CilOpCodes.Call, helpers["Push"]);
                    break;
                case SemanticOp.LdArg:
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Call, helpers["GetArg"]);
                    b.Instructions.Add(CilOpCodes.Call, helpers["Push"]);
                    break;
                case SemanticOp.LdLoc:
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Call, helpers["GetLoc"]);
                    b.Instructions.Add(CilOpCodes.Call, helpers["Push"]);
                    break;
                case SemanticOp.StLoc:
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Ldarg_0);
                    b.Instructions.Add(CilOpCodes.Call, helpers["Pop"]);
                    b.Instructions.Add(CilOpCodes.Call, helpers["SetLoc"]);
                    break;
                case SemanticOp.Br:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["Jump"]); break;
                case SemanticOp.BrTrue:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["JumpIfTrue"]); break;
                case SemanticOp.BrFalse:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["JumpIfFalse"]); break;
                case SemanticOp.Ret:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["Halt"]); break;
                case SemanticOp.NewObj:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmNewObj"]); break;
                case SemanticOp.LdFld:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmLdFld"]); break;
                case SemanticOp.StFld:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmStFld"]); break;
                case SemanticOp.Call:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmCall"]); break;
                case SemanticOp.CallVirt:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmCallVirt"]); break;
                case SemanticOp.LdElemI4:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmLdElemI4"]); break;
                case SemanticOp.StElemI4:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmStElemI4"]); break;
                case SemanticOp.LdLen:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmLdLen"]); break;
                case SemanticOp.Leave:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmLeave"]); break;
                case SemanticOp.EndFinally:
                    b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, helpers["VmEndFinally"]); break;
            }
            b.Instructions.Add(CilOpCodes.Ret);
        }

        if (cff) WrapWithCffAndOpaquePredicate(b, int32Type);
        m.CilMethodBody = b;
        vmType.Methods.Add(m);
        return m;
    }

    /// <summary>
    /// Wraps a straight-line method body in a switch-based Control-Flow Flattening (CFF) dispatcher
    /// with an algebraic opaque predicate `(x * (x + 1)) % 2 == 0` and a dead bogus block.
    /// </summary>
    private static void WrapWithCffAndOpaquePredicate(CilMethodBody body, TypeSignature int32Type) {
        var original = body.Instructions.ToList();
        body.Instructions.Clear();

        var stateVar = new CilLocalVariable(int32Type);
        var opaqueVar = new CilLocalVariable(int32Type);
        body.LocalVariables.Add(stateVar);
        body.LocalVariables.Add(opaqueVar);

        var dispatcherStart = new CilInstruction(CilOpCodes.Ldloc, stateVar);
        var case0 = new CilInstruction(CilOpCodes.Nop); // real body
        var case1 = new CilInstruction(CilOpCodes.Nop); // dead bogus block
        var case2 = new CilInstruction(CilOpCodes.Nop); // opaque predicate check -> jumps to case 0

        // Entry: state = 2; opaqueVar = 7; br dispatcher
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0x55 ^ 2);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0x55);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 7);
        body.Instructions.Add(CilOpCodes.Stloc, opaqueVar);

        // Dispatcher: ldloc state; switch (case0, case1, case2)
        body.Instructions.Add(dispatcherStart);
        body.Instructions.Add(CilOpCodes.Switch, new List<ICilLabel> {
            case0.CreateLabel(),
            case1.CreateLabel(),
            case2.CreateLabel()
        });
        body.Instructions.Add(CilOpCodes.Br, case0.CreateLabel());

        // Case 2: Opaque predicate (opaqueVar * (opaqueVar + 1)) % 2 == 0 -> always takes brfalse to state=0
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

        // Case 1: Dead bogus block
        body.Instructions.Add(case1);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 1337);
        body.Instructions.Add(CilOpCodes.Stloc, opaqueVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_0);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatcherStart.CreateLabel());

        // Case 0: Real original instructions
        body.Instructions.Add(case0);
        foreach (var ins in original)
            body.Instructions.Add(ins);
    }

    private static void EmitVmCtor(
        MethodDefinition vmCtor,
        IMethodDescriptor objectCtor,
        FieldDefinition tableField,
        TypeDefinition delType,
        MethodDefinition delCtor,
        IMethodDescriptor? dictCtor,
        IMethodDescriptor? dictAdd,
        Dictionary<SemanticOp, uint> opToKey,
        Dictionary<SemanticOp, MethodDefinition> handlerMethods,
        bool is32Bit,
        bool useCff,
        TypeSignature int32Type) {
        var b = new CilMethodBody();
        b.Instructions.Add(CilOpCodes.Ldarg_0);
        b.Instructions.Add(CilOpCodes.Call, objectCtor);

        if (is32Bit) {
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Newobj, dictCtor!);
            b.Instructions.Add(CilOpCodes.Stfld, tableField);

            foreach (var (op, key) in opToKey) {
                // Compute key via XOR expression in IL to prove emulation (not constant-only pattern scan) works!
                uint mask = 0x13572468u;
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldfld, tableField);
                b.Instructions.Add(CilOpCodes.Ldc_I4, unchecked((int)(key ^ mask)));
                b.Instructions.Add(CilOpCodes.Ldc_I4, unchecked((int)mask));
                b.Instructions.Add(CilOpCodes.Xor);
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldftn, handlerMethods[op]);
                b.Instructions.Add(CilOpCodes.Newobj, delCtor);
                b.Instructions.Add(CilOpCodes.Callvirt, dictAdd!);
            }
        }
        else {
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldc_I4, 256);
            b.Instructions.Add(CilOpCodes.Newarr, delType);
            b.Instructions.Add(CilOpCodes.Stfld, tableField);

            foreach (var (op, key) in opToKey) {
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldfld, tableField);
                b.Instructions.Add(CilOpCodes.Ldc_I4, (int)key);
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldftn, handlerMethods[op]);
                b.Instructions.Add(CilOpCodes.Newobj, delCtor);
                b.Instructions.Add(CilOpCodes.Stelem_Ref);
            }
        }

        b.Instructions.Add(CilOpCodes.Ret);

        if (useCff) WrapWithCffAndOpaquePredicate(b, int32Type);
        vmCtor.CilMethodBody = b;
    }

    private static void EmitVmStub(
        MethodDefinition method,
        MethodDefinition vmCtor,
        MethodDefinition vmEntry,
        int bytecodeOffset,
        TypeSignature objType,
        TypeSignature int32Type) {
        var b = new CilMethodBody();
        b.Instructions.Add(CilOpCodes.Newobj, vmCtor);
        b.Instructions.Add(CilOpCodes.Ldc_I4, method.Parameters.Count);
        b.Instructions.Add(CilOpCodes.Newarr, objType.ToTypeDefOrRef());
        for (int i = 0; i < method.Parameters.Count; i++) {
            b.Instructions.Add(CilOpCodes.Dup);
            b.Instructions.Add(CilOpCodes.Ldc_I4, i);
            b.Instructions.Add(CilOpCodes.Ldarg, method.Parameters[i]);
            if (method.Parameters[i].ParameterType.IsValueType)
                b.Instructions.Add(CilOpCodes.Box, method.Parameters[i].ParameterType.ToTypeDefOrRef());
            b.Instructions.Add(CilOpCodes.Stelem_Ref);
        }
        b.Instructions.Add(CilOpCodes.Ldc_I4, bytecodeOffset);
        b.Instructions.Add(CilOpCodes.Call, vmEntry);
        if (method.Signature!.ReturnType.IsValueType)
            b.Instructions.Add(CilOpCodes.Unbox_Any, method.Signature.ReturnType.ToTypeDefOrRef());
        else if (method.Signature.ReturnType.FullName != "System.Object")
            b.Instructions.Add(CilOpCodes.Castclass, method.Signature.ReturnType.ToTypeDefOrRef());
        b.Instructions.Add(CilOpCodes.Ret);
        method.CilMethodBody = b;
    }

    private sealed record EhClauseSpec(int Kind, int TryStart, int TryEnd, int HandlerStart, int HandlerEnd, int CatchTypeToken);
    private sealed record EncodedMethodBody(List<(SemanticOp Op, int Operand)> Instructions, List<EhClauseSpec> EhClauses);
    private sealed record MethodSpec(
        string Name,
        MethodSignature Signature,
        int LocalCount,
        Func<int, int, int, int, EncodedMethodBody> BuildOps);

    private static List<MethodSpec> BuildMethodSpecs(
        SyntheticTier tier,
        RuntimeContext? runtimeContext,
        CorLibTypeFactory corlib,
        TypeSignature int32,
        TypeSignature intArray,
        ITypeDefOrRef counterType,
        IMethodDescriptor counterCtor,
        IFieldDescriptor counterValue,
        IMethodDescriptor counterAddAndGet,
        ITypeDefOrRef divByZeroType) {
        var specs = new List<MethodSpec> {
            // 1. AddSubMul(a, b) => ((a + b) * 3) - (a - b)
            new(nameof(ReferenceSuite.AddSubMul), MethodSignature.CreateStatic(int32, [int32, int32]), 2, (_, _, _, _) => new([
                (SemanticOp.LdArg, 0), (SemanticOp.LdArg, 1), (SemanticOp.Add, 0), (SemanticOp.StLoc, 0),
                (SemanticOp.LdArg, 0), (SemanticOp.LdArg, 1), (SemanticOp.Sub, 0), (SemanticOp.StLoc, 1),
                (SemanticOp.LdLoc, 0), (SemanticOp.LdcI4, 3), (SemanticOp.Mul, 0), (SemanticOp.LdLoc, 1), (SemanticOp.Sub, 0),
                (SemanticOp.Ret, 0)
            ], [])),

            // 2. XorShiftMix(x, y) => ((x ^ y) + ((x & 0xFF) << 3)) ^ (y >> 2)
            new(nameof(ReferenceSuite.XorShiftMix), MethodSignature.CreateStatic(int32, [int32, int32]), 1, (_, _, _, _) => new([
                (SemanticOp.LdArg, 0), (SemanticOp.LdArg, 1), (SemanticOp.Xor, 0),
                (SemanticOp.LdArg, 0), (SemanticOp.LdcI4, 0xFF), (SemanticOp.And, 0), (SemanticOp.LdcI4, 3), (SemanticOp.Shl, 0),
                (SemanticOp.Add, 0), (SemanticOp.StLoc, 0),
                (SemanticOp.LdLoc, 0), (SemanticOp.LdArg, 1), (SemanticOp.LdcI4, 2), (SemanticOp.Shr, 0), (SemanticOp.Xor, 0),
                (SemanticOp.Ret, 0)
            ], [])),

            // 3. Clamp(v, min, max)
            new(nameof(ReferenceSuite.Clamp), MethodSignature.CreateStatic(int32, [int32, int32, int32]), 0, (_, _, _, _) => new([
                /*0*/ (SemanticOp.LdArg, 0), /*1*/ (SemanticOp.LdArg, 1), /*2*/ (SemanticOp.Clt, 0), /*3*/ (SemanticOp.BrFalse, 6),
                /*4*/ (SemanticOp.LdArg, 1), /*5*/ (SemanticOp.Ret, 0),
                /*6*/ (SemanticOp.LdArg, 0), /*7*/ (SemanticOp.LdArg, 2), /*8*/ (SemanticOp.Cgt, 0), /*9*/ (SemanticOp.BrFalse, 12),
                /*10*/ (SemanticOp.LdArg, 2), /*11*/ (SemanticOp.Ret, 0),
                /*12*/ (SemanticOp.LdArg, 0), /*13*/ (SemanticOp.Ret, 0)
            ], [])),

            // 4. SumRange(n)
            new(nameof(ReferenceSuite.SumRange), MethodSignature.CreateStatic(int32, [int32]), 2, (_, _, _, _) => new([
                /*0*/ (SemanticOp.LdcI4, 0), /*1*/ (SemanticOp.StLoc, 0),
                /*2*/ (SemanticOp.LdcI4, 1), /*3*/ (SemanticOp.StLoc, 1),
                /*4*/ (SemanticOp.LdLoc, 1), /*5*/ (SemanticOp.LdArg, 0), /*6*/ (SemanticOp.Cgt, 0), /*7*/ (SemanticOp.BrTrue, 17),
                /*8*/ (SemanticOp.LdLoc, 0), /*9*/ (SemanticOp.LdLoc, 1), /*10*/ (SemanticOp.Add, 0), /*11*/ (SemanticOp.StLoc, 0),
                /*12*/ (SemanticOp.LdLoc, 1), /*13*/ (SemanticOp.LdcI4, 1), /*14*/ (SemanticOp.Add, 0), /*15*/ (SemanticOp.StLoc, 1),
                /*16*/ (SemanticOp.Br, 4),
                /*17*/ (SemanticOp.LdLoc, 0), /*18*/ (SemanticOp.Ret, 0)
            ], [])),

            // 5. Gcd(a, b)
            new(nameof(ReferenceSuite.Gcd), MethodSignature.CreateStatic(int32, [int32, int32]), 3, (_, _, _, _) => new([
                /*0*/ (SemanticOp.LdArg, 0), /*1*/ (SemanticOp.StLoc, 0),
                /*2*/ (SemanticOp.LdArg, 1), /*3*/ (SemanticOp.StLoc, 1),
                /*4*/ (SemanticOp.LdLoc, 0), /*5*/ (SemanticOp.LdcI4, 0), /*6*/ (SemanticOp.Clt, 0), /*7*/ (SemanticOp.BrFalse, 11),
                /*8*/ (SemanticOp.LdLoc, 0), /*9*/ (SemanticOp.Neg, 0), /*10*/ (SemanticOp.StLoc, 0),
                /*11*/ (SemanticOp.LdLoc, 1), /*12*/ (SemanticOp.LdcI4, 0), /*13*/ (SemanticOp.Clt, 0), /*14*/ (SemanticOp.BrFalse, 18),
                /*15*/ (SemanticOp.LdLoc, 1), /*16*/ (SemanticOp.Neg, 0), /*17*/ (SemanticOp.StLoc, 1),
                /*18*/ (SemanticOp.LdLoc, 1), /*19*/ (SemanticOp.BrFalse, 29),
                /*20*/ (SemanticOp.LdLoc, 0), /*21*/ (SemanticOp.LdLoc, 1), /*22*/ (SemanticOp.Rem, 0), /*23*/ (SemanticOp.StLoc, 2),
                /*24*/ (SemanticOp.LdLoc, 1), /*25*/ (SemanticOp.StLoc, 0),
                /*26*/ (SemanticOp.LdLoc, 2), /*27*/ (SemanticOp.StLoc, 1),
                /*28*/ (SemanticOp.Br, 18),
                /*29*/ (SemanticOp.LdLoc, 0), /*30*/ (SemanticOp.Ret, 0)
            ], [])),

            // 6. ClassifyScore(score)
            new(nameof(ReferenceSuite.ClassifyScore), MethodSignature.CreateStatic(int32, [int32]), 0, (_, _, _, _) => new([
                /*0*/ (SemanticOp.LdArg, 0), /*1*/ (SemanticOp.LdcI4, 0), /*2*/ (SemanticOp.Clt, 0), /*3*/ (SemanticOp.BrFalse, 6),
                /*4*/ (SemanticOp.LdcI4, -1), /*5*/ (SemanticOp.Ret, 0),
                /*6*/ (SemanticOp.LdArg, 0), /*7*/ (SemanticOp.LdcI4, 50), /*8*/ (SemanticOp.Clt, 0), /*9*/ (SemanticOp.BrFalse, 12),
                /*10*/ (SemanticOp.LdcI4, 0), /*11*/ (SemanticOp.Ret, 0),
                /*12*/ (SemanticOp.LdArg, 0), /*13*/ (SemanticOp.LdcI4, 80), /*14*/ (SemanticOp.Clt, 0), /*15*/ (SemanticOp.BrFalse, 18),
                /*16*/ (SemanticOp.LdcI4, 1), /*17*/ (SemanticOp.Ret, 0),
                /*18*/ (SemanticOp.LdcI4, 2), /*19*/ (SemanticOp.Ret, 0)
            ], []))
        };

        if (tier >= SyntheticTier.Tier4_MultiEntryObjectsAndEh) {
            // 7. SumArray(int[] arr)
            specs.Add(new(nameof(ReferenceSuite.SumArray), MethodSignature.CreateStatic(int32, [intArray]), 2, (_, _, _, _) => new([
                /*0*/ (SemanticOp.LdcI4, 0), /*1*/ (SemanticOp.StLoc, 0),
                /*2*/ (SemanticOp.LdcI4, 0), /*3*/ (SemanticOp.StLoc, 1),
                /*4*/ (SemanticOp.LdLoc, 1), /*5*/ (SemanticOp.LdArg, 0), /*6*/ (SemanticOp.LdLen, 0), /*7*/ (SemanticOp.Clt, 0), /*8*/ (SemanticOp.BrFalse, 20),
                /*9*/ (SemanticOp.LdLoc, 0), /*10*/ (SemanticOp.LdArg, 0), /*11*/ (SemanticOp.LdLoc, 1), /*12*/ (SemanticOp.LdElemI4, 0), /*13*/ (SemanticOp.Add, 0), /*14*/ (SemanticOp.StLoc, 0),
                /*15*/ (SemanticOp.LdLoc, 1), /*16*/ (SemanticOp.LdcI4, 1), /*17*/ (SemanticOp.Add, 0), /*18*/ (SemanticOp.StLoc, 1),
                /*19*/ (SemanticOp.Br, 4),
                /*20*/ (SemanticOp.LdLoc, 0), /*21*/ (SemanticOp.Ret, 0)
            ], [])));

            // 8. CounterIncrement(ReferenceCounter counter, int delta)
            specs.Add(new(nameof(ReferenceSuite.CounterIncrement), MethodSignature.CreateStatic(int32, [counterType.ToTypeSignature(isValueType: false), int32]), 2,
                (_, tokVal, tokAdd, _) => new([
                    (SemanticOp.LdArg, 0), (SemanticOp.LdFld, tokVal), (SemanticOp.StLoc, 0),
                    (SemanticOp.LdArg, 0), (SemanticOp.LdArg, 1), (SemanticOp.CallVirt, tokAdd), (SemanticOp.StLoc, 1),
                    (SemanticOp.LdLoc, 0), (SemanticOp.LdLoc, 1), (SemanticOp.Add, 0), (SemanticOp.Ret, 0)
                ], [])));

            // 9. MakeCounter(int start)
            specs.Add(new(nameof(ReferenceSuite.MakeCounter), MethodSignature.CreateStatic(counterType.ToTypeSignature(isValueType: false), [int32]), 1,
                (tokCtor, tokVal, _, _) => new([
                    (SemanticOp.LdArg, 0), (SemanticOp.NewObj, tokCtor), (SemanticOp.StLoc, 0),
                    (SemanticOp.LdLoc, 0), (SemanticOp.LdLoc, 0), (SemanticOp.LdFld, tokVal), (SemanticOp.LdcI4, 10), (SemanticOp.Add, 0), (SemanticOp.StFld, tokVal),
                    (SemanticOp.LdLoc, 0), (SemanticOp.Ret, 0)
                ], [])));

            // 10. SafeDivide(int a, int b) — try { res = a / b; leave 9; } catch (DivideByZeroException) { stloc 1; res = -1; leave 9; } return res;
            specs.Add(new(nameof(ReferenceSuite.SafeDivide), MethodSignature.CreateStatic(int32, [int32, int32]), 2,
                (_, _, _, tokDbz) => new([
                    /*0*/ (SemanticOp.LdArg, 0), /*1*/ (SemanticOp.LdArg, 1), /*2*/ (SemanticOp.Div, 0), /*3*/ (SemanticOp.StLoc, 0), /*4*/ (SemanticOp.Leave, 9),
                    /*5*/ (SemanticOp.StLoc, 1), /*6*/ (SemanticOp.LdcI4, -1), /*7*/ (SemanticOp.StLoc, 0), /*8*/ (SemanticOp.Leave, 9),
                    /*9*/ (SemanticOp.LdLoc, 0), /*10*/ (SemanticOp.Ret, 0)
                ], [new EhClauseSpec(Kind: 0, TryStart: 0, TryEnd: 5, HandlerStart: 5, HandlerEnd: 9, CatchTypeToken: tokDbz)])));

            // 11. TryFinallyAccumulate(int a, int b) — acc = a; try { acc += b * 2; leave 14; } finally { acc += 7; endfinally; } return acc;
            specs.Add(new(nameof(ReferenceSuite.TryFinallyAccumulate), MethodSignature.CreateStatic(int32, [int32, int32]), 1,
                (_, _, _, _) => new([
                    /*0*/ (SemanticOp.LdArg, 0), /*1*/ (SemanticOp.StLoc, 0),
                    /*2*/ (SemanticOp.LdLoc, 0), /*3*/ (SemanticOp.LdArg, 1), /*4*/ (SemanticOp.LdcI4, 2), /*5*/ (SemanticOp.Mul, 0), /*6*/ (SemanticOp.Add, 0), /*7*/ (SemanticOp.StLoc, 0), /*8*/ (SemanticOp.Leave, 14),
                    /*9*/ (SemanticOp.LdLoc, 0), /*10*/ (SemanticOp.LdcI4, 7), /*11*/ (SemanticOp.Add, 0), /*12*/ (SemanticOp.StLoc, 0), /*13*/ (SemanticOp.EndFinally, 0),
                    /*14*/ (SemanticOp.LdLoc, 0), /*15*/ (SemanticOp.Ret, 0)
                ], [new EhClauseSpec(Kind: 1, TryStart: 2, TryEnd: 9, HandlerStart: 9, HandlerEnd: 14, CatchTypeToken: 0)])));
        }

        return specs;
    }

    private static bool HasOperand(SemanticOp op) => op is
        SemanticOp.LdcI4 or SemanticOp.LdArg or SemanticOp.LdLoc or SemanticOp.StLoc or
        SemanticOp.Br or SemanticOp.BrTrue or SemanticOp.BrFalse or SemanticOp.Leave or
        SemanticOp.NewObj or SemanticOp.LdFld or SemanticOp.StFld or SemanticOp.Call or SemanticOp.CallVirt;

    private static byte[] EncryptBytecode(byte[] plain, uint seed, uint step) {
        byte[] enc = new byte[plain.Length];
        uint key = seed;
        for (int i = 0; i < plain.Length; i++) {
            enc[i] = (byte)(plain[i] ^ (key & 0xFF));
            key = unchecked(key + step);
        }
        return enc;
    }
}
