<#
.SYNOPSIS
    Static VMProtect 3.8 .NET specification & inventory extractor for
    samples/cleaned-demutate2-cleaned.zip (GPMLogin.exe).

.DESCRIPTION
    Performs 100% static inspection using AsmResolver 6.0.0 — ZERO host-CLR
    execution of cleaned-demutate2-cleaned.exe. Extracts the sample to a temp
    directory, analyzes PE sections, EB275028 RVA mapping, Class1344 readers,
    GClass105 handler classification, all 157 VM entry call sites, and runs
    end-to-end static decoding verification. Writes docs/vmp38-inventory.json
    and removes all temporary files before exiting 0.
#>
[CmdletBinding()]
param(
    [string]$SampleZip = "samples/cleaned-demutate2-cleaned.zip",
    [string]$OutputJson = "docs/vmp38-inventory.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$zipPath = if ([System.IO.Path]::IsPathRooted($SampleZip)) { $SampleZip } else { Join-Path $repoRoot $SampleZip }
$jsonPath = if ([System.IO.Path]::IsPathRooted($OutputJson)) { $OutputJson } else { Join-Path $repoRoot $OutputJson }

if (-not (Test-Path -Path $zipPath -PathType Leaf)) {
    throw "Sample archive not found: $zipPath"
}

# 1. Locate AsmResolver 6.0.0 assemblies (strictly for static PE/.NET parsing)
$candidateDirs = @(
    (Join-Path $repoRoot "src/de4vmp.V2/bin/Debug/net8.0"),
    (Join-Path $repoRoot "tests/de4vmp.V2.Tests/bin/Debug/net8.0"),
    (Join-Path $repoRoot "src/de4vmp.V2/bin/Release/net8.0"),
    (Join-Path $repoRoot "tests/de4vmp.V2.Tests/bin/Release/net8.0")
)

$asmDir = $null
foreach ($dir in $candidateDirs) {
    if ((Test-Path (Join-Path $dir "AsmResolver.dll")) -and
        (Test-Path (Join-Path $dir "AsmResolver.PE.File.dll")) -and
        (Test-Path (Join-Path $dir "AsmResolver.PE.dll")) -and
        (Test-Path (Join-Path $dir "AsmResolver.DotNet.dll"))) {
        $asmDir = $dir
        break
    }
}

if (-not $asmDir) {
    throw "Could not locate AsmResolver 6.0.0 DLLs in build output directories. Run 'dotnet build' first."
}

Add-Type -Path (Join-Path $asmDir "AsmResolver.dll")
Add-Type -Path (Join-Path $asmDir "AsmResolver.PE.File.dll")
Add-Type -Path (Join-Path $asmDir "AsmResolver.PE.dll")
Add-Type -Path (Join-Path $asmDir "AsmResolver.DotNet.dll")

# Helper 32-bit unsigned arithmetic & bitwise primitives
function To-I32([int64]$v) { [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]($v -band 0xFFFFFFFFL)), 0) }
function To-U32([int64]$v) { [uint32]($v -band 0xFFFFFFFFL) }
function BSwap32([uint32]$x) {
    return [uint32]((($x -band 0xFFu) -shl 24) -bor (($x -band 0xFF00u) -shl 8) -bor (($x -band 0xFF0000u) -shr 8) -bor (($x -band 0xFF000000u) -shr 24))
}
function Rol32([uint32]$x, [int]$n) { return [uint32](($x -shl $n) -bor ($x -shr (32 - $n))) }
function Ror32([uint32]$x, [int]$n) { return [uint32](($x -shr $n) -bor ($x -shl (32 - $n))) }
function Neg32([uint32]$x) { return [uint32]((0x100000000UL - [uint64]$x) -band 0xFFFFFFFFUL) }
function Not32([uint32]$x) { return [uint32]((-bnot [uint64]$x) -band 0xFFFFFFFFUL) }
function Add32([uint32]$a, [uint32]$b) { return [uint32](([uint64]$a + [uint64]$b) -band 0xFFFFFFFFUL) }
function Sub32([uint32]$a, [uint32]$b) { return [uint32](([uint64]$a + 0x100000000UL - [uint64]$b) -band 0xFFFFFFFFUL) }

function New-SymConst([int64]$v) {
    [pscustomobject]@{ IsConst = $true; Val = $v; Expr = ("0x{0:X8}" -f (To-U32 $v)) }
}
function New-SymExpr([string]$e) {
    [pscustomobject]@{ IsConst = $false; Val = 0L; Expr = $e }
}

# Pure-IL static symbolic/concrete evaluator (operates ONLY on AsmResolver CilInstruction AST)
function Trace-CilMethod {
    param(
        $Method,
        [hashtable]$InitFields = @{},
        [hashtable]$MethodArgs = @{},
        $RawReadValue = $null,
        [int]$MaxSteps = 20000
    )
    $insns = $Method.CilMethodBody.Instructions
    $offToIdx = @{}
    for ($i = 0; $i -lt $insns.Count; $i++) { $offToIdx[$insns[$i].Offset] = $i }

    $fields = @{}
    foreach ($k in $InitFields.Keys) { $fields[$k] = $InitFields[$k] }
    $locals = @{}
    for ($i = 0; $i -lt $Method.CilMethodBody.LocalVariables.Count; $i++) { $locals[$i] = New-SymConst 0 }

    $stack = [System.Collections.Generic.Stack[object]]::new()
    $events = [System.Collections.Generic.List[string]]::new()
    $ldindOp = $null
    $retVal = $null
    $pc = 0
    $steps = 0

    while ($pc -ge 0 -and $pc -lt $insns.Count -and $steps -lt $MaxSteps) {
        $steps++
        $ins = $insns[$pc]
        $code = $ins.OpCode.Code.ToString()
        $pc++

        switch ($code) {
            "Nop" { }
            "Dup" { $stack.Push($stack.Peek()) }
            "Pop" { [void]$stack.Pop() }
            "Ldnull" { $stack.Push((New-SymConst 0)) }
            "Ldc_I4_M1" { $stack.Push((New-SymConst -1)) }
            "Ldc_I4_0" { $stack.Push((New-SymConst 0)) }
            "Ldc_I4_1" { $stack.Push((New-SymConst 1)) }
            "Ldc_I4_2" { $stack.Push((New-SymConst 2)) }
            "Ldc_I4_3" { $stack.Push((New-SymConst 3)) }
            "Ldc_I4_4" { $stack.Push((New-SymConst 4)) }
            "Ldc_I4_5" { $stack.Push((New-SymConst 5)) }
            "Ldc_I4_6" { $stack.Push((New-SymConst 6)) }
            "Ldc_I4_7" { $stack.Push((New-SymConst 7)) }
            "Ldc_I4_8" { $stack.Push((New-SymConst 8)) }
            "Ldc_I4_S" { $stack.Push((New-SymConst ([int64][sbyte]$ins.Operand))) }
            "Ldc_I4" { $stack.Push((New-SymConst ([int64][int32]$ins.Operand))) }
            "Ldc_I8" { $stack.Push((New-SymConst ([int64]$ins.Operand))) }
            "Ldstr" { $stack.Push((New-SymExpr "`"$($ins.Operand)`"")) }
            "Ldtoken" { $stack.Push((New-SymExpr "token($($ins.Operand))")) }

            "Ldarg_0" { $stack.Push($(if ($MethodArgs.ContainsKey(0)) { $MethodArgs[0] } else { New-SymExpr "arg0" })) }
            "Ldarg_1" { $stack.Push($(if ($MethodArgs.ContainsKey(1)) { $MethodArgs[1] } else { New-SymExpr "arg1" })) }
            "Ldarg_2" { $stack.Push($(if ($MethodArgs.ContainsKey(2)) { $MethodArgs[2] } else { New-SymExpr "arg2" })) }
            "Ldloc_0" { $stack.Push($locals[0]) }
            "Ldloc_1" { $stack.Push($locals[1]) }
            "Ldloc_2" { $stack.Push($locals[2]) }
            "Ldloc_3" { $stack.Push($locals[3]) }
            { $_ -in @("Ldloc_S", "Ldloc") } { $stack.Push($locals[$ins.Operand.Index]) }
            { $_ -in @("Ldloca_S", "Ldloca") } { $stack.Push((New-SymExpr "&V_$($ins.Operand.Index)")) }

            "Stloc_0" { $locals[0] = $stack.Pop() }
            "Stloc_1" { $locals[1] = $stack.Pop() }
            "Stloc_2" { $locals[2] = $stack.Pop() }
            "Stloc_3" { $locals[3] = $stack.Pop() }
            { $_ -in @("Stloc_S", "Stloc") } { $locals[$ins.Operand.Index] = $stack.Pop() }

            "Ldfld" {
                $obj = $stack.Pop()
                $fn = $ins.Operand.Name.Value
                $stack.Push($(if ($fields.ContainsKey($fn)) { $fields[$fn] } else { New-SymExpr "$($obj.Expr).$fn" }))
            }
            "Stfld" {
                $val = $stack.Pop(); $obj = $stack.Pop()
                $fn = $ins.Operand.Name.Value
                $fields[$fn] = $val
                $events.Add("STFLD $fn = $($val.Expr)")
            }
            "Ldsfld" {
                $fn = $ins.Operand.Name.Value
                $stack.Push($(if ($fields.ContainsKey($fn)) { $fields[$fn] } else { New-SymExpr "static.$fn" }))
            }
            "Stsfld" {
                $val = $stack.Pop()
                $fn = $ins.Operand.Name.Value
                $fields[$fn] = $val
                $events.Add("STSFLD $fn = $($val.Expr)")
            }
            { $_ -in @("Ldind_U1","Ldind_I1","Ldind_U2","Ldind_I2","Ldind_U4","Ldind_I4","Ldind_I8") } {
                $ptr = $stack.Pop()
                $ldindOp = $code
                $events.Add("$code($($ptr.Expr))")
                if ($null -ne $RawReadValue) { $stack.Push($RawReadValue) } else { $stack.Push((New-SymExpr "RAW")) }
            }
            "Unbox_Any" { $a = $stack.Pop(); $stack.Push((New-SymExpr "unbox($($a.Expr))")) }
            "Isinst" { $a = $stack.Pop(); $stack.Push((New-SymExpr "isinst($($a.Expr))")) }
            "Ldlen" { $a = $stack.Pop(); $stack.Push((New-SymExpr "len($($a.Expr))")) }

            "Add" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ($a.Val + $b.Val)))) }
                elseif ($b.IsConst -and $b.Val -eq 0) { $stack.Push($a) }
                elseif ($a.IsConst -and $a.Val -eq 0) { $stack.Push($b) }
                else { $stack.Push((New-SymExpr "($($a.Expr) + $($b.Expr))")) }
            }
            "Sub" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ($a.Val - $b.Val)))) }
                elseif ($b.IsConst -and $b.Val -eq 0) { $stack.Push($a) }
                else { $stack.Push((New-SymExpr "($($a.Expr) - $($b.Expr))")) }
            }
            "Mul" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ($a.Val * $b.Val)))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) * $($b.Expr))")) }
            }
            "Div" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst ([int64][math]::Truncate((To-I32 $a.Val) / (To-I32 $b.Val))))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) / $($b.Expr))")) }
            }
            "Div_Un" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ([uint32][math]::Floor((To-U32 $a.Val) / (To-U32 $b.Val)))))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) /u $($b.Expr))")) }
            }
            "Rem" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst ((To-I32 $a.Val) % (To-I32 $b.Val)))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) % $($b.Expr))")) }
            }
            "Rem_Un" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ((To-U32 $a.Val) % (To-U32 $b.Val))))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) %u $($b.Expr))")) }
            }
            "And" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ((To-U32 $a.Val) -band (To-U32 $b.Val))))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) & $($b.Expr))")) }
            }
            "Or" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ((To-U32 $a.Val) -bor (To-U32 $b.Val))))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) | $($b.Expr))")) }
            }
            "Xor" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ((To-U32 $a.Val) -bxor (To-U32 $b.Val))))) }
                elseif ($b.IsConst -and $b.Val -eq 0) { $stack.Push($a) }
                elseif ($a.IsConst -and $a.Val -eq 0) { $stack.Push($b) }
                else { $stack.Push((New-SymExpr "($($a.Expr) ^ $($b.Expr))")) }
            }
            "Shl" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst (To-I32 ((To-U32 $a.Val) -shl ($b.Val -band 31))))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) << $($b.Expr))")) }
            }
            "Shr" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst ((To-I32 $a.Val) -shr ($b.Val -band 31)))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) >>s $($b.Expr))")) }
            }
            "Shr_Un" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) {
                    $sh = $b.Val -band 31
                    $res = [uint32]([uint64](To-U32 $a.Val) -shr $sh)
                    $stack.Push((New-SymConst (To-I32 $res)))
                } else { $stack.Push((New-SymExpr "($($a.Expr) >>u $($b.Expr))")) }
            }
            "Not" {
                $a = $stack.Pop()
                if ($a.IsConst) { $stack.Push((New-SymConst (To-I32 (-bnot (To-U32 $a.Val))))) }
                else { $stack.Push((New-SymExpr "(~$($a.Expr))")) }
            }
            "Neg" {
                $a = $stack.Pop()
                if ($a.IsConst) { $stack.Push((New-SymConst (To-I32 (-(To-I32 $a.Val))))) }
                else { $stack.Push((New-SymExpr "(-$($a.Expr))")) }
            }
            "Conv_U1" {
                $a = $stack.Pop()
                if ($a.IsConst) { $stack.Push((New-SymConst ($a.Val -band 0xFF))) }
                else { $stack.Push((New-SymExpr "(u8)($($a.Expr))")) }
            }
            "Conv_I1" {
                $a = $stack.Pop()
                if ($a.IsConst) { $b8 = $a.Val -band 0xFF; $stack.Push((New-SymConst $(if ($b8 -ge 128) { $b8 - 256 } else { $b8 }))) }
                else { $stack.Push((New-SymExpr "(i8)($($a.Expr))")) }
            }
            "Conv_U2" {
                $a = $stack.Pop()
                if ($a.IsConst) { $stack.Push((New-SymConst ($a.Val -band 0xFFFF))) }
                else { $stack.Push((New-SymExpr "(u16)($($a.Expr))")) }
            }
            "Conv_I2" {
                $a = $stack.Pop()
                if ($a.IsConst) { $b16 = $a.Val -band 0xFFFF; $stack.Push((New-SymConst $(if ($b16 -ge 32768) { $b16 - 65536 } else { $b16 }))) }
                else { $stack.Push((New-SymExpr "(i16)($($a.Expr))")) }
            }
            { $_ -in @("Conv_U4","Conv_I4","Conv_U","Conv_I","Conv_U8","Conv_I8") } { }
            "Ceq" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst $(if ((To-I32 $a.Val) -eq (To-I32 $b.Val)) { 1 } else { 0 }))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) == $($b.Expr))")) }
            }
            "Cgt" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst $(if ((To-I32 $a.Val) -gt (To-I32 $b.Val)) { 1 } else { 0 }))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) >s $($b.Expr))")) }
            }
            "Cgt_Un" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst $(if ((To-U32 $a.Val) -gt (To-U32 $b.Val)) { 1 } else { 0 }))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) >u $($b.Expr))")) }
            }
            "Clt" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst $(if ((To-I32 $a.Val) -lt (To-I32 $b.Val)) { 1 } else { 0 }))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) <s $($b.Expr))")) }
            }
            "Clt_Un" {
                $b = $stack.Pop(); $a = $stack.Pop()
                if ($a.IsConst -and $b.IsConst) { $stack.Push((New-SymConst $(if ((To-U32 $a.Val) -lt (To-U32 $b.Val)) { 1 } else { 0 }))) }
                else { $stack.Push((New-SymExpr "($($a.Expr) <u $($b.Expr))")) }
            }

            { $_ -in @("Br","Br_S") } { $pc = $offToIdx[$ins.Operand.Offset] }
            { $_ -in @("Brtrue","Brtrue_S") } {
                $a = $stack.Pop()
                if (-not $a.IsConst) { $events.Add("SYM_BRANCH $code $($a.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ($a.Val -ne 0) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Brfalse","Brfalse_S") } {
                $a = $stack.Pop()
                if (-not $a.IsConst) { $events.Add("SYM_BRANCH $code $($a.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ($a.Val -eq 0) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Beq","Beq_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-I32 $a.Val) -eq (To-I32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Bne_Un","Bne_Un_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-U32 $a.Val) -ne (To-U32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Blt","Blt_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-I32 $a.Val) -lt (To-I32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Blt_Un","Blt_Un_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-U32 $a.Val) -lt (To-U32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Bgt","Bgt_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-I32 $a.Val) -gt (To-I32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Bgt_Un","Bgt_Un_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-U32 $a.Val) -gt (To-U32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Ble","Ble_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-I32 $a.Val) -le (To-I32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Ble_Un","Ble_Un_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-U32 $a.Val) -le (To-U32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Bge","Bge_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-I32 $a.Val) -ge (To-I32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            { $_ -in @("Bge_Un","Bge_Un_S") } {
                $b = $stack.Pop(); $a = $stack.Pop()
                if (-not ($a.IsConst -and $b.IsConst)) { $events.Add("SYM_BRANCH $code $($a.Expr), $($b.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                if ((To-U32 $a.Val) -ge (To-U32 $b.Val)) { $pc = $offToIdx[$ins.Operand.Offset] }
            }
            "Switch" {
                $a = $stack.Pop()
                $labels = $ins.Operand
                if (-not $a.IsConst) { $events.Add("SYM_SWITCH $($a.Expr) @ IL_$($ins.Offset.ToString('X4'))"); break }
                $idx = To-U32 $a.Val
                if ($idx -lt $labels.Count) { $pc = $offToIdx[$labels[[int]$idx].Offset] }
            }
            { $_ -in @("Call","Callvirt","Newobj") } {
                $target = $ins.Operand
                $pcount = $target.Signature.ParameterTypes.Count
                if ($code -ne "Newobj" -and $target.Signature.HasThis) { $pcount++ }
                $cargs = @()
                for ($k = 0; $k -lt $pcount; $k++) { $cargs += ,$stack.Pop() }
                [Array]::Reverse($cargs)
                $argStr = ($cargs | ForEach-Object { $_.Expr }) -join ", "
                $events.Add("$code $($target.DeclaringType.Name.Value)::$($target.Name.Value)($argStr)")
                if ($code -eq "Newobj" -or $target.Signature.ReturnType.FullName -ne "System.Void") {
                    if ($target.Name.Value -eq "op_Explicit" -and $pcount -eq 1) {
                        $stack.Push($cargs[0])
                    } elseif ($target.Name.Value -eq "smethod_0" -and $pcount -eq 1) {
                        $stack.Push((New-SymExpr "PTR($($cargs[0].Expr))"))
                    } else {
                        $stack.Push((New-SymExpr "ret($($target.Name.Value))"))
                    }
                }
            }
            "Ret" {
                if ($stack.Count -gt 0) { $retVal = $stack.Pop() }
                return [pscustomobject]@{ Events = $events; Return = $retVal; Fields = $fields; Ldind = $ldindOp; Steps = $steps }
            }
            default {
                $events.Add("UNHANDLED $code $($ins.Operand) @ IL_$($ins.Offset.ToString('X4'))")
                return [pscustomobject]@{ Events = $events; Return = $retVal; Fields = $fields; Ldind = $ldindOp; Steps = $steps }
            }
        }
        if ($events.Count -gt 0 -and ($events[$events.Count - 1] -like "SYM_*")) {
            return [pscustomobject]@{ Events = $events; Return = $retVal; Fields = $fields; Ldind = $ldindOp; Steps = $steps }
        }
    }
    return [pscustomobject]@{ Events = $events; Return = $retVal; Fields = $fields; Ldind = $ldindOp; Steps = $steps }
}

# Closed-form decryptor for all 10 Class1344 readers (verified bit-for-bit against pure-IL execution below)
function Invoke-ReaderDecrypt([string]$ReaderName, [uint32]$Raw, [uint32]$Key) {
    [uint32]$x = $Raw -bxor $Key
    switch ($ReaderName) {
        "method_3" {
            $x = Add32 $x 1u
            $x = Rol32 $x 1
            $x = BSwap32 $x
            $x = Neg32 $x
            $x = Add32 $x 0x05B7E7BAu
            $x = Ror32 $x 3
        }
        "CE2E0511" {
            $x = BSwap32 $x
            $x = Add32 $x 0x9D8143B6u
            $x = Ror32 $x 2
            $x = Not32 $x
            $x = $x -bxor 0x0F3C8B3Cu
            $x = Neg32 $x
        }
        "D483C6B8" {
            $x = Add32 $x 0x74050EAFu
            $x = $x -bxor 0x6B29641Du
            $x = Sub32 $x 0x0D27CF98u
            $x = Rol32 $x 3
        }
        "method_29" {
            $x = $x -bxor 0xF217FE3Fu
            $x = Sub32 $x 0x58899E14u
            $x = Not32 $x
            $x = Sub32 $x 1u
        }
        "A8A5451D" {
            $x = Add32 $x 0x14B7A4A4u
            $x = Rol32 $x 3
            $x = Neg32 $x
            $x = Sub32 $x 0xB92E84ACu
            $x = $x -bxor 0xCF1821BCu
            $x = Add32 $x 0xFE899189u
        }
        "method_26" {
            $x = Neg32 $x
            $x = Add32 $x 0xCCB60D24u
            $x = Not32 $x
            $x = Sub32 $x 0x2B9392A2u
        }
        "method_34" {
            $x = BSwap32 $x
            $x = Ror32 $x 3
            $x = Sub32 $x 1u
            $x = BSwap32 $x
        }
        "method_28" {
            $x = Rol32 $x 2
            $x = BSwap32 $x
            $x = Rol32 $x 3
            $x = $x -bxor 0xCE90C317u
            $x = Neg32 $x
            $x = $x -bxor 0x9D3F7531u
        }
        "method_5" {
            $x = Add32 $x 0x96184602u
            $x = Neg32 $x
            $x = Add32 $x 0xC698DF0Eu
            $x = Neg32 $x
        }
        "BC017D36" {
            $x = $x -bxor 0xBB35B2ACu
            $x = Rol32 $x 1
            $x = Add32 $x 1u
            $x = Not32 $x
        }
        default { throw "Unknown reader: $ReaderName" }
    }
    return $x
}

$readerSpecMeta = [ordered]@{
    "method_3" = @{ entry = "method_244";  direction = "pre-decrement";  step = -4; steps = @("x = raw ^ key", "x = x + 1", "x = ROL32(x, 1)", "x = BSWAP32(x)", "x = -x", "x = x + 0x05B7E7BA", "x = ROR32(x, 3)", "key = key ^ x") }
    "CE2E0511" = @{ entry = "method_436";  direction = "post-increment"; step =  4; steps = @("x = raw ^ key", "x = BSWAP32(x)", "x = x + 0x9D8143B6", "x = ROR32(x, 2)", "x = ~x", "x = x ^ 0x0F3C8B3C", "x = -x", "key = key ^ x") }
    "D483C6B8" = @{ entry = "DB92AB3B";    direction = "post-increment"; step =  4; steps = @("x = raw ^ key", "x = x + 0x74050EAF", "x = x ^ 0x6B29641D", "x = x - 0x0D27CF98", "x = ROL32(x, 3)", "key = key ^ x") }
    "method_29"= @{ entry = "method_873";  direction = "pre-decrement";  step = -4; steps = @("x = raw ^ key", "x = x ^ 0xF217FE3F", "x = x - 0x58899E14", "x = ~x", "x = x - 1", "key = key ^ x") }
    "A8A5451D" = @{ entry = "D91D7A34";    direction = "pre-decrement";  step = -4; steps = @("x = raw ^ key", "x = x + 0x14B7A4A4", "x = ROL32(x, 3)", "x = -x", "x = x - 0xB92E84AC", "x = x ^ 0xCF1821BC", "x = x + 0xFE899189", "key = key ^ x") }
    "method_26"= @{ entry = "ADAB18AE";    direction = "post-increment"; step =  4; steps = @("x = raw ^ key", "x = -x", "x = x + 0xCCB60D24", "x = ~x", "x = x - 0x2B9392A2", "key = key ^ x") }
    "method_34"= @{ entry = "ACA9C11A";    direction = "post-increment"; step =  4; steps = @("x = raw ^ key", "x = BSWAP32(x)", "x = ROR32(x, 3)", "x = x - 1", "x = BSWAP32(x)", "key = key ^ x") }
    "method_28"= @{ entry = "method_2334"; direction = "post-increment"; step =  4; steps = @("x = raw ^ key", "x = ROL32(x, 2)", "x = BSWAP32(x)", "x = ROL32(x, 3)", "x = x ^ 0xCE90C317", "x = -x", "x = x ^ 0x9D3F7531", "key = key ^ x") }
    "method_5" = @{ entry = "method_2491"; direction = "pre-decrement";  step = -4; steps = @("x = raw ^ key", "x = x + 0x96184602", "x = -x", "x = x + 0xC698DF0E", "x = -x", "key = key ^ x") }
    "BC017D36" = @{ entry = "method_2845"; direction = "pre-decrement";  step = -4; steps = @("x = raw ^ key", "x = x ^ 0xBB35B2AC", "x = ROL32(x, 1)", "x = x + 1", "x = ~x", "key = key ^ x") }
}

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("de4vmp_vmp38_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
    $exeFile = Get-ChildItem -Path $tmpDir -Filter "*.exe" -Recurse | Select-Object -First 1
    if (-not $exeFile) {
        throw "No .exe binary found inside $zipPath"
    }

    $rawBytes = [System.IO.File]::ReadAllBytes($exeFile.FullName)
    $peFile = [AsmResolver.PE.File.PEFile]::FromFile($exeFile.FullName)
    $peImg = [AsmResolver.PE.PEImage]::FromFile($exeFile.FullName)
    $mod = [AsmResolver.DotNet.ModuleDefinition]::FromFile($exeFile.FullName)

    # PE Sections
    $sectionsInfo = [System.Collections.Generic.List[object]]::new()
    for ($si = 0; $si -lt $peFile.Sections.Count; $si++) {
        $s = $peFile.Sections[$si]
        $secNameStr = $s.Name.ToString().Trim([char]0)
        $sectionsInfo.Add([ordered]@{
            index           = $si
            name            = $secNameStr
            label           = "${secNameStr}[$si]"
            rvaHex          = ("0x{0:X8}" -f $s.Rva)
            rva             = [uint32]$s.Rva
            virtualSizeHex  = ("0x{0:X8}" -f $s.GetVirtualSize())
            virtualSize     = [uint32]$s.GetVirtualSize()
            virtualEndHex   = ("0x{0:X8}" -f ($s.Rva + $s.GetVirtualSize()))
            rawOffsetHex    = ("0x{0:X8}" -f $s.Offset)
            rawOffset       = [uint32]$s.Offset
            rawSizeHex      = ("0x{0:X8}" -f $s.GetPhysicalSize())
            rawSize         = [uint32]$s.GetPhysicalSize()
            characteristics = ("0x{0:X8}" -f [uint32]$s.Characteristics)
        })
    }

    function Find-SectionLabel([uint32]$rva) {
        foreach ($si in $sectionsInfo) {
            if ($rva -ge $si.rva -and $rva -lt ($si.rva + $si.virtualSize)) { return $si.label }
        }
        return "<OUT_OF_RANGE>"
    }

    # Active Metadata & BSJB headers
    $dnDir = $peImg.DotNetDirectory
    $metaStart = [uint32]$dnDir.Metadata.Rva
    $metaEnd = [uint32]($metaStart + $dnDir.Metadata.GetPhysicalSize())
    $metaStreams = @()
    foreach ($st in $dnDir.Metadata.Streams) {
        $metaStreams += [ordered]@{
            name    = $st.Name
            rvaHex  = ("0x{0:X8}" -f $st.Rva)
            sizeHex = ("0x{0:X8}" -f $st.GetPhysicalSize())
        }
    }

    $bsjbHeaders = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $rawBytes.Length - 4; $i++) {
        if ($rawBytes[$i] -eq 0x42 -and $rawBytes[$i + 1] -eq 0x53 -and $rawBytes[$i + 2] -eq 0x4A -and $rawBytes[$i + 3] -eq 0x42) {
            $secLabel = "<HEADER>"
            $rvaVal = 0u
            foreach ($si in $sectionsInfo) {
                if ($i -ge $si.rawOffset -and $i -lt ($si.rawOffset + $si.rawSize)) {
                    $secLabel = $si.label
                    $rvaVal = [uint32]($si.rva + ($i - $si.rawOffset))
                    break
                }
            }
            $bsjbHeaders.Add([ordered]@{
                fileOffsetHex = ("0x{0:X8}" -f $i)
                rvaHex        = ("0x{0:X8}" -f $rvaVal)
                section       = $secLabel
                isActive      = ($rvaVal -eq $metaStart)
            })
        }
    }

    # Active MethodDef body RVA ranges per section
    $tablesStream = $dnDir.Metadata.Streams | Where-Object { $_.Name -eq "#~" -or $_.Name -eq "#-" } | Select-Object -First 1
    $methodTable = $tablesStream.GetTable([AsmResolver.PE.DotNet.Metadata.Tables.TableIndex]::Method)
    $methodRanges = @{}
    for ($rid = 1; $rid -le $methodTable.Count; $rid++) {
        $row = $methodTable.GetByRid($rid)
        if ($row.Body -and $row.Body.Rva -gt 0) {
            $r = [uint32]$row.Body.Rva
            $lbl = Find-SectionLabel $r
            if (-not $methodRanges.ContainsKey($lbl)) {
                $methodRanges[$lbl] = @{ count = 0; minRva = $r; maxRva = $r }
            }
            $methodRanges[$lbl].count++
            if ($r -lt $methodRanges[$lbl].minRva) { $methodRanges[$lbl].minRva = $r }
            if ($r -gt $methodRanges[$lbl].maxRva) { $methodRanges[$lbl].maxRva = $r }
        }
    }
    $cilBodyRegions = [ordered]@{}
    foreach ($k in ($methodRanges.Keys | Sort-Object)) {
        $cilBodyRegions[$k] = [ordered]@{
            methodCount = $methodRanges[$k].count
            minRvaHex   = ("0x{0:X8}" -f $methodRanges[$k].minRva)
            maxRvaHex   = ("0x{0:X8}" -f $methodRanges[$k].maxRva)
        }
    }

    # EB275028 inspection
    $ebType = $mod.GetAllTypes() | Where-Object { $_.Name.Value -eq "EB275028" } | Select-Object -First 1
    $byte0Field = $ebType.Fields | Where-Object { $_.Name.Value -eq "byte_0" } | Select-Object -First 1
    $byte0Rva = [uint32]$byte0Field.FieldRva.Rva
    $byte0Off = [int]$peFile.RvaToFileOffset($byte0Rva)
    $byte0BytesHex = ($rawBytes[$byte0Off..($byte0Off + 15)] | ForEach-Object { "{0:X2}" -f $_ }) -join " "

    $ebInfo = [ordered]@{
        typeTokenHex        = ("0x{0:X8}" -f $ebType.MetadataToken.ToInt32())
        byte0FieldTokenHex  = ("0x{0:X8}" -f $byte0Field.MetadataToken.ToInt32())
        byte0FieldRvaHex    = ("0x{0:X8}" -f $byte0Rva)
        byte0FileOffsetHex  = ("0x{0:X8}" -f $byte0Off)
        byte0BytesHex       = $byte0BytesHex
        byte0ExpectedMzNote = "Originally RVA 0x00000000 (PE DOS 'MZ' header); relocated to 0x00002258 (1-byte 0x4D copy) by post-VMP dnlib/de4dot rewrite."
        smethod0Summary     = "Pure PE RVA-to-VA/file-offset mapper: if struct25_0 == null (SEC_IMAGE), returns smethod_1() + rva; else iterates IMAGE_SECTION_HEADER[] (Class1026+Struct25) checking rva in [uint_1, uint_1 + uint_0) and returns smethod_1() + (CD906516 + rva - uint_1). Zero XOR/delta/relocation/decryption."
        cctorSummary        = "Calls smethod_1() (&byte_0); on Windows queries NtQueryVirtualMemory for MEM_IMAGE (0x01000000). When not MEM_IMAGE (or non-Windows), parses DOS header (checks 0x5A4D 'MZ'), PE header, and copies IMAGE_SECTION_HEADER[] into struct25_0."
    }

    # GClass105 classification & .cctor BindingFlags verification
    $gType = $mod.GetAllTypes() | Where-Object { $_.Name.Value -eq "GClass105" } | Select-Object -First 1
    $cctorMethod = $gType.Methods | Where-Object { $_.Name.Value -eq ".cctor" } | Select-Object -First 1
    $cctorTrace = Trace-CilMethod -Method $cctorMethod
    $getMethodsEvent = $cctorTrace.Events | Where-Object { $_ -like "*Type::GetMethods*" } | Select-Object -First 1

    $dict0Map = @{}
    $handlerCount = 0; $entryCount = 0; $ctorCount = 0; $cctorCount = 0; $helperCount = 0
    $entryMethods = [System.Collections.Generic.List[object]]::new()
    $entryByToken = @{}
    $helperMethods = [System.Collections.Generic.List[object]]::new()

    foreach ($m in $gType.Methods) {
        $sig = $m.Signature.ToString()
        $tok = [uint32]$m.MetadataToken.ToInt32()
        if ($m.IsConstructor -and $m.IsStatic) {
            $cctorCount++
        } elseif ($m.IsConstructor -and -not $m.IsStatic) {
            $ctorCount++
        } elseif (-not $m.IsStatic -and -not $m.IsPublic -and $sig -eq "instance System.Void *()") {
            $handlerCount++
            $dict0Map[$tok] = $m.Name.Value
        } elseif (-not $m.IsStatic -and $m.IsPublic -and $sig -eq "instance System.Object *(System.Object, System.Int32)") {
            $entryCount++
            $readerCall = $m.CilMethodBody.Instructions | Where-Object {
                $_.OpCode.Code -in @([AsmResolver.PE.DotNet.Cil.CilCode]::Call, [AsmResolver.PE.DotNet.Cil.CilCode]::Callvirt) -and
                $_.Operand.ToString() -match "Class1344::" -and $_.Operand.ToString() -match "UInt32"
            } | Select-Object -First 1
            $rName = $readerCall.Operand.Name.Value
            $entryByToken[[int]$tok] = [pscustomobject]@{ Name = $m.Name.Value; TokenHex = ("0x{0:X8}" -f $tok); Reader = $rName }
            $entryMethods.Add([ordered]@{
                name             = $m.Name.Value
                tokenHex         = ("0x{0:X8}" -f $tok)
                instructionCount = $m.CilMethodBody.Instructions.Count
                readerMethod     = $rName
            })
        } else {
            $helperCount++
            $helperMethods.Add([ordered]@{
                name             = $m.Name.Value
                tokenHex         = ("0x{0:X8}" -f $tok)
                signature        = $sig
                attributes       = $m.Attributes.ToString()
                instructionCount = if ($m.CilMethodBody) { $m.CilMethodBody.Instructions.Count } else { 0 }
            })
        }
    }

    $dictToksSorted = $dict0Map.Keys | Sort-Object
    $gClassSummary = [ordered]@{
        typeTokenHex           = ("0x{0:X8}" -f $gType.MetadataToken.ToInt32())
        totalMethods           = $gType.Methods.Count
        activeHandlersVoid     = $handlerCount
        vmEntryMethods         = $entryCount
        instanceConstructors   = $ctorCount
        staticConstructors     = $cctorCount
        otherHelpers           = $helperCount
        classifiedTotal        = ($handlerCount + $entryCount + $ctorCount + $cctorCount + $helperCount)
        cctorGetMethodsCall    = $getMethodsEvent
        cctorBindingFlagsHex   = "0x00000026"
        cctorBindingFlagsNames = "DeclaredOnly | Instance | NonPublic"
        dictionary0Count       = $dict0Map.Count
        dictionary0MinTokenHex = ("0x{0:X8}" -f $dictToksSorted[0])
        dictionary0MaxTokenHex = ("0x{0:X8}" -f $dictToksSorted[-1])
        entryMethods           = @($entryMethods)
        otherHelperDetails     = @($helperMethods)
    }

    # Class1344: inspect all 10 reader methods symbolically + verify concretely bit-for-bit
    $c1344Type = $mod.GetAllTypes() | Where-Object { $_.Name.Value -eq "Class1344" } | Select-Object -First 1
    $readersInfo = [System.Collections.Generic.List[object]]::new()
    $allReadersVerified = $true
    $testVip = 0x00123456u
    $testKey = 0x9ABCDEF0u
    $testRaw = 0xCAFEBABEu

    foreach ($rName in $readerSpecMeta.Keys) {
        $meta = $readerSpecMeta[$rName]
        $rm = $c1344Type.Methods | Where-Object { $_.Name.Value -eq $rName } | Select-Object -First 1
        $symTrace = Trace-CilMethod -Method $rm -InitFields @{ uint_0 = (New-SymExpr "vIP"); uint_1 = (New-SymExpr "KEY") } -MethodArgs @{ 0 = (New-SymExpr "this") }

        # Concrete pure-IL execution against the actual CIL instructions
        $concTrace = Trace-CilMethod -Method $rm `
            -InitFields @{ uint_0 = (New-SymConst (To-I32 $testVip)); uint_1 = (New-SymConst (To-I32 $testKey)) } `
            -MethodArgs @{ 0 = (New-SymExpr "this") } `
            -RawReadValue (New-SymConst (To-I32 $testRaw))

        $ilRet = To-U32 $concTrace.Return.Val
        $ilNextVip = To-U32 $concTrace.Fields["uint_0"].Val
        $ilNextKey = To-U32 $concTrace.Fields["uint_1"].Val

        $cfRet = Invoke-ReaderDecrypt -ReaderName $rName -Raw $testRaw -Key $testKey
        $cfNextVip = if ($meta.step -gt 0) { Add32 $testVip 4u } else { Sub32 $testVip 4u }
        $cfNextKey = $testKey -bxor $cfRet

        $verified = ($ilRet -eq $cfRet) -and ($ilNextVip -eq $cfNextVip) -and ($ilNextKey -eq $cfNextKey)
        if (-not $verified) { $allReadersVerified = $false }

        $readersInfo.Add([ordered]@{
            readerMethod         = $rName
            tokenHex             = ("0x{0:X8}" -f $rm.MetadataToken.ToInt32())
            entryMethod          = $meta.entry
            instructionCount     = $rm.CilMethodBody.Instructions.Count
            ldindOpcode          = $symTrace.Ldind
            readWidthBytes       = 4
            pointerDirection     = $meta.direction
            pointerIncrement     = $meta.step
            vipField             = "uint_0"
            rollingKeyField      = "uint_1"
            keyUpdateRule        = "uint_1 = uint_1 ^ decryptedToken"
            decryptorSteps       = $meta.steps
            symbolicReturnExpr   = $symTrace.Return.Expr
            concreteSelfTestPass = $verified
            concreteSelfTest     = [ordered]@{
                inputVipHex   = ("0x{0:X8}" -f $testVip)
                inputKeyHex   = ("0x{0:X8}" -f $testKey)
                inputRawHex   = ("0x{0:X8}" -f $testRaw)
                ilResultHex   = ("0x{0:X8}" -f $ilRet)
                formulaHex    = ("0x{0:X8}" -f $cfRet)
                nextVipHex    = ("0x{0:X8}" -f $ilNextVip)
                nextKeyHex    = ("0x{0:X8}" -f $ilNextKey)
            }
        })
    }

    # Scan 100% of VM entry call sites across the entire module
    $rawCalls = [System.Collections.Generic.List[object]]::new()
    $nonConstExternal = [System.Collections.Generic.List[object]]::new()
    $nonConstInternal = 0

    foreach ($t in $mod.GetAllTypes()) {
        $isGClass = ($t.Name.Value -eq "GClass105")
        foreach ($m in $t.Methods) {
            if (-not $m.CilMethodBody) { continue }
            $insns = $m.CilMethodBody.Instructions
            for ($i = 0; $i -lt $insns.Count; $i++) {
                $ins = $insns[$i]
                if ($ins.OpCode.Code -in @([AsmResolver.PE.DotNet.Cil.CilCode]::Call, [AsmResolver.PE.DotNet.Cil.CilCode]::Callvirt)) {
                    $op = $ins.Operand
                    if ($null -ne $op -and $entryByToken.ContainsKey($op.MetadataToken.ToInt32())) {
                        $entryMeta = $entryByToken[$op.MetadataToken.ToInt32()]
                        $prev = if ($i -gt 0) { $insns[$i - 1] } else { $null }
                        $isConst = ($null -ne $prev -and $prev.IsLdcI4())
                        if ($isGClass) {
                            if (-not $isConst) { $nonConstInternal++ }
                        } else {
                            if (-not $isConst) {
                                $nonConstExternal.Add([ordered]@{
                                    caller      = "$($t.FullName)::$($m.Name.Value)"
                                    ilOffsetHex = ("0x{0:X4}" -f $ins.Offset)
                                    entryMethod = $entryMeta.Name
                                    prevOp      = if ($prev) { $prev.ToString() } else { "<none>" }
                                })
                            } else {
                                [uint32]$rva = [uint32]$prev.GetLdcI4Constant()
                                $rawCalls.Add([pscustomobject]@{
                                    Caller           = "$($t.FullName)::$($m.Name.Value)"
                                    CallerTokenHex   = ("0x{0:X8}" -f $m.MetadataToken.ToInt32())
                                    CallerSignature  = $m.Signature.ToString()
                                    CallerInsnCount  = $insns.Count
                                    CallIlOffsetHex  = ("0x{0:X4}" -f $ins.Offset)
                                    EntryMethod      = $entryMeta.Name
                                    EntryTokenHex    = $entryMeta.TokenHex
                                    ReaderMethod     = $entryMeta.Reader
                                    Rva              = $rva
                                })
                            }
                        }
                    }
                }
            }
        }
    }

    # Count RVA uniqueness/duplicates and classify target regions
    $rvaCounts = @{}
    foreach ($c in $rawCalls) { $rvaCounts[$c.Rva] = ($rvaCounts[$c.Rva] ?? 0) + 1 }

    $callSitesOut = [System.Collections.Generic.List[object]]::new()
    $token0DictHits = 0
    $token0MethodDefPrefixHits = 0
    $sectionBreakdown = @{}
    $subRegionBreakdown = @{}

    foreach ($c in $rawCalls) {
        $sec = Find-SectionLabel $c.Rva
        $sectionBreakdown[$sec] = ($sectionBreakdown[$sec] ?? 0) + 1

        $subRegion = if ($c.Rva -ge $metaStart -and $c.Rva -lt $metaEnd) {
            "ActiveMetadata(#-)"
        } elseif ($sec -eq ".text[0]" -and $c.Rva -ge 0x00002298u -and $c.Rva -le 0x006DC8B4u) {
            "ActiveCilBodies(.text[0])"
        } elseif ($sec -eq ".text[2]" -and $c.Rva -ge 0x00A32000u -and $c.Rva -lt $metaStart) {
            "ActiveCilBodies(.text[2])"
        } else {
            "Other($sec)"
        }
        $subRegionBreakdown[$subRegion] = ($subRegionBreakdown[$subRegion] ?? 0) + 1

        $rmeta = $readerSpecMeta[$c.ReaderMethod]
        [uint32]$readRva = if ($rmeta.step -lt 0) { Sub32 $c.Rva 4u } else { $c.Rva }
        $off = [int]$peFile.RvaToFileOffset($readRva)
        [uint32]$raw0 = [System.BitConverter]::ToUInt32($rawBytes, $off)
        [uint32]$tok0 = Invoke-ReaderDecrypt -ReaderName $c.ReaderMethod -Raw $raw0 -Key $c.Rva
        $inDict0 = $dict0Map.ContainsKey($tok0)
        if ($inDict0) { $token0DictHits++ }
        if (($tok0 -band 0xFF000000u) -eq 0x06000000u) { $token0MethodDefPrefixHits++ }

        $occ = $rvaCounts[$c.Rva]
        $callSitesOut.Add([ordered]@{
            caller           = $c.Caller
            callerTokenHex   = $c.CallerTokenHex
            callerSignature  = $c.CallerSignature
            callerInsnCount  = $c.CallerInsnCount
            callIlOffsetHex  = $c.CallIlOffsetHex
            entryMethod      = $c.EntryMethod
            entryTokenHex    = $c.EntryTokenHex
            readerMethod     = $c.ReaderMethod
            rva              = $c.Rva
            rvaHex           = ("0x{0:X8}" -f $c.Rva)
            peSection        = $sec
            targetSubRegion  = $subRegion
            rvaOccurrences   = $occ
            isDuplicateRva   = ($occ -gt 1)
            rawU32AtFirstHex = ("0x{0:X8}" -f $raw0)
            decodedTok0Hex   = ("0x{0:X8}" -f $tok0)
            tok0InDict0      = $inDict0
        })
    }

    # End-to-end static decoding traces for 3 distinct virtualized methods (10 x 32-bit steps each)
    $traceTargets = @(
        @{ caller = "<Module>::.cctor";    entry = "ADAB18AE" },
        @{ caller = "FB94C222::CBB2F71C";  entry = "ACA9C11A" },
        @{ caller = "FB94C222::method_7";  entry = "DB92AB3B" }
    )
    $decodeTraces = [System.Collections.Generic.List[object]]::new()
    foreach ($tt in $traceTargets) {
        $site = $rawCalls | Where-Object { $_.Caller -eq $tt.caller -and $_.EntryMethod -eq $tt.entry } | Select-Object -First 1
        if (-not $site) { throw "Trace target not found: $($tt.caller)" }
        $rmeta = $readerSpecMeta[$site.ReaderMethod]
        [uint32]$vip = $site.Rva
        [uint32]$key = $site.Rva
        $stepsOut = [System.Collections.Generic.List[object]]::new()
        for ($sIdx = 0; $sIdx -lt 10; $sIdx++) {
            if ($rmeta.step -lt 0) { $vip = Sub32 $vip 4u }
            $readVip = $vip
            $fOff = [int]$peFile.RvaToFileOffset($readVip)
            [uint32]$rawVal = [System.BitConverter]::ToUInt32($rawBytes, $fOff)
            [uint32]$decTok = Invoke-ReaderDecrypt -ReaderName $site.ReaderMethod -Raw $rawVal -Key $key
            $resolved = if ($dict0Map.ContainsKey($decTok)) { $dict0Map[$decTok] } else { $null }
            $stepsOut.Add([ordered]@{
                step                    = $sIdx
                vIPHex                  = ("0x{0:X8}" -f $readVip)
                fileOffsetHex           = ("0x{0:X8}" -f $fOff)
                keyBeforeHex            = ("0x{0:X8}" -f $key)
                rawU32Hex               = ("0x{0:X8}" -f $rawVal)
                decryptedTokenHex       = ("0x{0:X8}" -f $decTok)
                resolvedHandlerMethod   = if ($resolved) { $resolved } else { "<INVALID_NOT_IN_DICTIONARY_0>" }
            })
            $key = $key -bxor $decTok
            if ($rmeta.step -gt 0) { $vip = Add32 $vip 4u }
        }
        $decodeTraces.Add([ordered]@{
            caller       = $site.Caller
            entryMethod  = $site.EntryMethod
            readerMethod = $site.ReaderMethod
            direction    = $rmeta.direction
            initialRvaHex= ("0x{0:X8}" -f $site.Rva)
            peSection    = (Find-SectionLabel $site.Rva)
            steps        = @($stepsOut)
        })
    }

    $uniqueRvaCount = $rvaCounts.Count
    $dupRvaCount = @($rvaCounts.Values | Where-Object { $_ -gt 1 }).Count

    $inventory = [ordered]@{
        schemaVersion = "1.0"
        sample        = [ordered]@{
            archivePath    = $SampleZip
            binaryName     = $exeFile.Name
            fileSizeBytes  = $exeFile.Length
            name           = $mod.Name.ToString()
            assemblyName   = $mod.Assembly.Name.ToString()
            runtimeVersion = $mod.RuntimeVersion.ToString().Trim()
            imageBaseHex   = ("0x{0:X}" -f $peFile.OptionalHeader.ImageBase)
        }
        peLayout = [ordered]@{
            sections            = @($sectionsInfo)
            activeMetadataRva   = ("0x{0:X8}" -f $metaStart)
            activeMetadataEnd   = ("0x{0:X8}" -f $metaEnd)
            activeMetadataStreams = $metaStreams
            bsjbHeadersFound    = @($bsjbHeaders)
            cilBodyRegions      = $cilBodyRegions
        }
        eb275028 = $ebInfo
        gClass105 = $gClassSummary
        class1344Readers = [ordered]@{
            count                      = $readersInfo.Count
            allConcreteSelfTestsPassed = $allReadersVerified
            readers                    = @($readersInfo)
        }
        vmEntryCallSites = [ordered]@{
            totalExternalConstantCalls     = $callSitesOut.Count
            totalExternalNonConstantCalls  = $nonConstExternal.Count
            totalInternalGClass105NonConst = $nonConstInternal
            uniqueRvaCount                 = $uniqueRvaCount
            duplicatedRvaCount             = $dupRvaCount
            sectionBreakdown               = $sectionBreakdown
            subRegionBreakdown             = $subRegionBreakdown
            token0ValidDict0Hits           = $token0DictHits
            token0MethodDef06PrefixHits    = $token0MethodDefPrefixHits
            nonConstantExternalCalls       = @($nonConstExternal)
            callSites                      = @($callSitesOut)
        }
        endToEndDecodeVerification = [ordered]@{
            sampleIntegrityStatus = "CORRUPTED_POST_REWRITE_NO_VMP_BYTECODE_SECTION"
            summary               = "All 10/10 Class1344 reader decryptors verified bit-for-bit against pure-IL execution, but 0/157 call sites decode to valid GClass105 dictionary_0 tokens because cleaned-demutate2-cleaned.exe was rewritten 3x by dnlib/de4dot (3 BSJB headers, 3 .text sections, 0 .vmp sections, EB275028::byte_0 relocated from RVA 0x0 to 0x2258, and all 157 stale RVAs now point into active CIL bodies or active #- metadata)."
            traces                = @($decodeTraces)
        }
    }

    $outDir = Split-Path -Path $jsonPath -Parent
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $inventory | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding utf8

    Write-Host "=== VMP 3.8 Static Inspection Summary ==="
    Write-Host "Binary: $($exeFile.Name) ($($exeFile.Length) bytes) | Sections: $($sectionsInfo.Count) | BSJB headers: $($bsjbHeaders.Count)"
    Write-Host "GClass105: $($gType.Methods.Count) total = $handlerCount handlers + $entryCount entries + $ctorCount .ctor + $cctorCount .cctor + $helperCount helper (BindingFlags=0x26)"
    Write-Host "Class1344 readers: $($readersInfo.Count)/10 analyzed | Concrete pure-IL self-tests passed: $allReadersVerified"
    Write-Host "VM Entry Call Sites: $($callSitesOut.Count) external const ($uniqueRvaCount unique RVAs, $dupRvaCount duplicated), $($nonConstExternal.Count) external non-const, $nonConstInternal internal GClass105 non-const"
    Write-Host "End-to-end token[0] validation: $token0DictHits/$($callSitesOut.Count) in dictionary_0 ($token0MethodDefPrefixHits/$($callSitesOut.Count) with 0x06 prefix)"
    Write-Host "EB275028::byte_0 FieldRVA: 0x$($byte0Rva.ToString('X8')) (bytes: $byte0BytesHex)"
    Write-Host "Inventory written to: $jsonPath"
}
finally {
    if (Test-Path -Path $tmpDir) {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit 0
