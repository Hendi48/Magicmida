// ====================================================================
//
// Delphi Static lib for BeaEngine 5.x
//
// Last update: 2022-03-15
// Supported compilers: Delphi 2009 - Delphi 11
// ====================================================================
// BeaEngine.pas convert by Vince
// updated by kao, Hendi
// ====================================================================
unit BeaEngineDelphi32;
// ====================================================================
// Default link type is static lib
// comment below line to switch link with DLL
// ====================================================================
//{$DEFINE USEDLL}
// ====================================================================
// Copyright 2006-2009, BeatriX
// File coded by BeatriX
//
// This file is part of BeaEngine.
//
// BeaEngine is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// BeaEngine is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with BeaEngine.  If not, see <http://www.gnu.org/licenses/>.

interface

uses Windows;

const
  INSTRUCT_LENGTH = 64;

type
  TREX_Struct = packed record
    W_: UInt8;
    R_: UInt8;
    X_: UInt8;
    B_: UInt8;
    state: UInt8;
  end;

  TPREFIXINFO = packed record
    Number: Integer;
    NbUndefined: Integer;
    LockPrefix: UInt8;
    OperandSize: UInt8;
    AddressSize: UInt8;
    RepnePrefix: UInt8;
    RepPrefix: UInt8;
    FSPrefix: UInt8;
    SSPrefix: UInt8;
    GSPrefix: UInt8;
    ESPrefix: UInt8;
    CSPrefix: UInt8;
    DSPrefix: UInt8;
    BranchTaken: UInt8;
    BranchNotTaken: UInt8;
    REX: TREX_Struct;
    alignment: array[0..1] of Byte;
  end;

  TEFLStruct = packed record
    OF_: UInt8;
    SF_: UInt8;
    ZF_: UInt8;
    AF_: UInt8;
    PF_: UInt8;
    CF_: UInt8;
    TF_: UInt8;
    IF_: UInt8;
    DF_: UInt8;
    NT_: UInt8;
    RF_: UInt8;
    alignment: UInt8;
  end;

  TMEMORYTYPE = packed record
    BaseRegister: Int64;
    IndexRegister: Int64;
    Scale: Int32;
    Displacement: Int64;
  end;

  TREGISTERTYPE = packed record
    rtype: Int64;
    gpr: Int64;
    mmx: Int64;
    xmm: Int64;
    ymm: Int64;
    zmm: Int64;
    special: Int64;
    cr: Int64;
    dr: Int64;
    mem_management: Int64;
    mpx: Int64;
    opmask: Int64;
    segment: Int64;
    fpu: Int64;
  end;

  TINSTRTYPE = packed record
    Category: Int32;
    Opcode: Int32;
    Mnemonic: array[0..23] of AnsiChar;
    BranchType: Int32;
    Flags: TEFLStruct;
    AddrValue: UInt64;
    Immediat: Int64;
    ImplicitModifiedRegs: TREGISTERTYPE;
  end;

  TOPTYPE = packed record
    OpMnemonic: array[0..23] of AnsiChar;
    OpType: Int64;
    OpSize: Int32;
    OpPosition: Int32;
    AccessMode: UInt32;
    Memory: TMEMORYTYPE;
    Registers : TREGISTERTYPE;
    SegmentReg: UInt32;
  end;

  TDisasm = packed record
    EIP: UIntPtr;
    VirtualAddr: UInt64;
    SecurityBlock: UInt32;
    CompleteInstr: array[0..(INSTRUCT_LENGTH - 1)] of AnsiChar;
    Archi: UInt32;
    Options: UInt64;
    Instruction: TINSTRTYPE;
    Operand1: TOPTYPE;
    Operand2: TOPTYPE;
    Operand3: TOPTYPE;
    Operand4: TOPTYPE;
    Prefix: TPREFIXINFO;
    Error: UInt32;
    Reserved_: array[0..48] of UInt32;
  end;
  PDISASM = ^TDisasm;
  LPDISASM = ^TDisasm;

const
  ESReg = 1;
  DSReg = 2;
  FSReg = 3;
  GSReg = 4;
  CSReg = 5;
  SSReg = 6;
  InvalidPrefix = 4;
  SuperfluousPrefix = 2;
  NotUsedPrefix = 0;
  MandatoryPrefix = 8;
  InUsePrefix = 1;

type
  INSTRUCTION_TYPE = Integer;

const
  GENERAL_PURPOSE_INSTRUCTION   =           $10000;
  FPU_INSTRUCTION               =           $20000;
  MMX_INSTRUCTION               =           $30000;
  SSE_INSTRUCTION               =           $40000;
  SSE2_INSTRUCTION              =           $50000;
  SSE3_INSTRUCTION              =           $60000;
  SSSE3_INSTRUCTION             =           $70000;
  SSE41_INSTRUCTION             =           $80000;
  SSE42_INSTRUCTION             =           $90000;
  SYSTEM_INSTRUCTION            =           $a0000;
  VM_INSTRUCTION                =           $b0000;
  UNDOCUMENTED_INSTRUCTION      =           $c0000;
  AMD_INSTRUCTION               =           $d0000;
  ILLEGAL_INSTRUCTION           =           $e0000;
  AES_INSTRUCTION               =           $f0000;
  CLMUL_INSTRUCTION             =          $100000;
  AVX_INSTRUCTION               =          $110000;
  AVX2_INSTRUCTION              =          $120000;
  MPX_INSTRUCTION               =          $130000;
  AVX512_INSTRUCTION            =          $140000;
  SHA_INSTRUCTION               =          $150000;
  BMI2_INSTRUCTION              =          $160000;
  CET_INSTRUCTION               =          $170000;
  BMI1_INSTRUCTION              =          $180000;
  XSAVEOPT_INSTRUCTION          =          $190000;
  FSGSBASE_INSTRUCTION          =          $1a0000;
  CLWB_INSTRUCTION              =          $1b0000;
  CLFLUSHOPT_INSTRUCTION        =          $1c0000;
  FXSR_INSTRUCTION              =          $1d0000;
  XSAVE_INSTRUCTION             =          $1e0000;
  SGX_INSTRUCTION               =          $1f0000;
  PCONFIG_INSTRUCTION           =          $200000;

  DATA_TRANSFER = $1;
  ARITHMETIC_INSTRUCTION = 2;
  LOGICAL_INSTRUCTION = 3;
  SHIFT_ROTATE = 4;
  BIT_BYTE = 5;
  CONTROL_TRANSFER = 6;
  STRING_INSTRUCTION = 7;
  InOutINSTRUCTION = 8;
  ENTER_LEAVE_INSTRUCTION = 9;
  FLAG_CONTROL_INSTRUCTION = 10;
  SEGMENT_REGISTER = 11;
  MISCELLANEOUS_INSTRUCTION = 12;
  COMPARISON_INSTRUCTION = 13;
  LOGARITHMIC_INSTRUCTION = 14;
  TRIGONOMETRIC_INSTRUCTION = 15;
  UNSUPPORTED_INSTRUCTION = 16;
  LOAD_CONSTANTS = 17;
  FPUCONTROL = 18;
  STATE_MANAGEMENT = 19;
  CONVERSION_INSTRUCTION = 20;
  SHUFFLE_UNPACK = 21;
  PACKED_SINGLE_PRECISION = 22;
  SIMD128bits = 23;
  SIMD64bits = 24;
  CACHEABILITY_CONTROL = 25;
  FP_INTEGER_CONVERSION = 26;
  SPECIALIZED_128bits = 27;
  SIMD_FP_PACKED = 28;
  SIMD_FP_HORIZONTAL = 29;
  AGENT_SYNCHRONISATION = 30;
  PACKED_ALIGN_RIGHT = 31;
  PACKED_SIGN = 32;
  PACKED_BLENDING_INSTRUCTION = 33;
  PACKED_TEST = 34;
  PACKED_MINMAX = 35;
  HORIZONTAL_SEARCH = 36;
  PACKED_EQUALITY = 37;
  STREAMING_LOAD = 38;
  INSERTION_EXTRACTION = 39;
  DOT_PRODUCT = 40;
  SAD_INSTRUCTION = 41;
  ACCELERATOR_INSTRUCTION = 42; // crc32, popcnt (sse4.2)
  ROUND_INSTRUCTION = 43;

type
  EFLAGS_STATES = Integer;

const
  TE_ = 1;
  MO_ = 2;
  RE_ = 4;
  SE_ = 8;
  UN_ = $10;
  PR_ = $20;

type
  BRANCH_TYPE = Integer;

const
  JO = 1;
  JC = 2;
  JE = 3;
  JA = 4;
  JS = 5;
  JP = 6;
  JL = 7;
  JG = 8;
  JB = 2;
  JECXZ = 10;
  JmpType = 11;
  CallType = 12;
  RetType = 13;
  JNO = -(1);
  JNC = -(2);
  JNE = -(3);
  JNA = -(4);
  JNS = -(5);
  JNP = -(6);
  JNL = -(7);
  JNG = -(8);
  JNB = -(2);

type
  ARGUMENTS_TYPE = Integer;

const
  NO_ARGUMENT = $10000;
  REGISTER_TYPE = $20000;
  MEMORY_TYPE = $30000;
  CONSTANT_TYPE = $40000;


  GENERAL_REG =               $1;
  MMX_REG =                   $2;
  SSE_REG =                   $4;
  AVX_REG =                   $8;
  AVX512_REG =                $10;
  SPECIAL_REG =               $20;
  CR_REG =                    $40;
  DR_REG =                    $80;
  MEMORY_MANAGEMENT_REG =     $100;
  MPX_REG =                   $200;
  OPMASK_REG =                $400;
  SEGMENT_REG =               $800;
  FPU_REG =                   $1000;

  RELATIVE_ = $4000000;
  ABSOLUTE_ = $8000000;

  READ = $1;
  WRITE = $2;

  /// <summary>RAX / MM0 / ST0 / XMM0 / CR0 / DR0 / GDTR / ES</summary>
  REG0 = $1;
  /// <summary>RCX / MM1 / ST1 / XMM1 / CR1 / DR1 / LDTR / CS</summary>
  REG1 = $2;
  /// <summary>RDX / MM2 / ST2 / XMM2 / CR2 / DR2 / IDTR / SS</summary>
  REG2 = $4;
  /// <summary>RBX / MM3 / ST3 / XMM3 / CR3 / DR3 / TR   / DS</summary>
  REG3 = $8;
  /// <summary>RSP / MM4 / ST4 / XMM4 / CR4 / DR4 / ---- / FS</summary>
  REG4 = $10;
  /// <summary>RBP / MM5 / ST5 / XMM5 / CR5 / DR5 / ---- / GS</summary>
  REG5 = $20;
  /// <summary>RSI / MM6 / ST6 / XMM6 / CR6 / DR6 / ---- / --</summary>
  REG6 = $40;
  /// <summary>RDI / MM7 / ST7 / XMM7 / CR7 / DR7 / ---- / --</summary>
  REG7 = $80;
  REG8 = $100;
  REG9 = $200;
  REG10 = $400;
  REG11 = $800;
  REG12 = $1000;
  REG13 = $2000;
  REG14 = $4000;
  REG15 = $8000;

type
  SPECIAL_INFO = Integer;

Const
  UNKNOWN_OPCODE = -(1);
  OUT_OF_BLOCK = -(2);
  { === mask = 0xff }
  NoTabulation = $00000000;
  Tabulation = $00000001;
  { === mask = 0xff00 }
  MasmSyntax = $00000000;
  GoAsmSyntax = $00000100;
  NasmSyntax = $00000200;
  ATSyntax = $00000400;
  IntrinsicMemSyntax = $00000800;
  { === mask = 0xff0000 }
  PrefixedNumeral = $00010000;
  SuffixedNumeral = $00000000;
  { === mask = 0xff000000 }
  ShowSegmentRegs = $01000000;
  LowPosition = 0;
  HighPosition = 1;

function Disasm(var aDisAsm: TDisasm): Integer; stdcall;
function BeaEngineVersion: PAnsiChar; stdcall;
function BeaEngineRevision: PAnsiChar; stdcall;

implementation

{$IFNDEF USEDLL}
{$IFNDEF WIN64}
{$L BeaEngineLib.obj}
uses SysUtils;
{$ELSE}
{$L BeaEngineLib64.obj}
uses AnsiStrings;
{$ENDIF}

function {$IFNDEF WIN64}_strcmp{$ELSE}strcmp{$ENDIF}(Str1, Str2: PAnsiChar): Integer; cdecl;
begin
  Result := StrComp(Str1, Str2);
end;

function {$IFNDEF WIN64}_strcpy{$ELSE}strcpy{$ENDIF}(dest, src: PAnsiChar): PAnsiChar; cdecl;
begin
  Result := StrCopy(dest, src);
end;

function _strlen(s: PAnsiChar): Cardinal; cdecl;
begin
  Result := StrLen(s);
end;

function {$IFNDEF WIN64}_memset{$ELSE}memset{$ENDIF}(Destination: Pointer; C: Integer; Count: NativeUInt): Pointer; cdecl;
begin
  FillMemory(Destination, Count, C);
  Result := Destination;
end;

function _memcpy(Dst, src: Pointer; Count: Cardinal): Pointer; cdecl;
begin
  CopyMemory(Dst, src, Count);
  Result := Dst;
end;

function {$IFNDEF WIN64}_sprintf{$ELSE}sprintf{$ENDIF}(Buffer, Format: PAnsiChar): Integer; varargs; cdecl; external 'msvcrt.dll' name 'sprintf'; // not using user32_wsprintfA because it fails on %.16llX

function Disasm(var aDisAsm: TDisasm): Integer; stdcall; external;
function BeaEngineVersion: PAnsiChar; stdcall; external;
function BeaEngineRevision: PAnsiChar; stdcall; external;

{$ELSE}
function Disasm(var aDisAsm: TDisasm): Integer; stdcall; external 'BeaEngine.DLL' name '_Disasm@4';
function BeaEngineVersion: PAnsiChar; stdcall; external 'BeaEngine.DLL' name '_BeaEngineVersion@0';
function BeaEngineRevision: PAnsiChar; stdcall; external 'BeaEngine.DLL' name '_BeaEngineRevision@0';

{$ENDIF}

end.
