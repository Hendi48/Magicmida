unit Dumper;

interface

uses Windows, SysUtils, Classes, Generics.Collections, {$IFNDEF FPC}TlHelp32{$ELSE}JwaTlHelp32{$ENDIF},
     PEInfo, Utils, Math;

const
  MAX_IAT_SIZE = 5120 * SizeOf(Pointer); // max 5K imports

type
  TExportTable = TDictionary<Pointer, string>;

  TRemoteModule = record
    Base, EndOff: PByte;
    Name: string;
    ExportTbl: TExportTable;
  end;
  PRemoteModule = ^TRemoteModule;

  TForwardDict = TDictionary<Pointer, Pointer>;

  TImportThunk = class
  public
    Module: PRemoteModule;
    Name: string;
    Addresses: TList<PPointer>;

    constructor Create(RM: PRemoteModule);
    destructor Destroy; override;
  end;

  TDumper = class
  private
    FProcess: TProcessInformation;
    FOEP, FIAT, FImageBase: NativeUInt;
    FForwards: TForwardDict; // Key: NTDLL, Value: kernel32 (points to API)
    FForwardsType2: TForwardDict; // Key: NTDLL, Value: user32 (points to fwd-string)
    FForwardsOle32: TForwardDict; // Key: combase, Value: ole32
    FForwardsNetapi32: TForwardDict; // Key: netutils, Value: netapi32
    FForwardsCrypt32: TForwardDict; // Key: DPAPI, Value: crypt32
    FForwardsDbghelp: TForwardDict; // Key: dbgcore, Value: dbghelp
    FForwardsKernelbase: TForwardDict; // Key: NTDLL, Value: kernelbase (Win8 sync APIs like WakeByAddressAll)
    FAllModules: TList<PRemoteModule>;
    FIATImage: PByte;
    FIATImageSize: Cardinal;

    FUsrPath: string;
    FHUsr: HMODULE;

    procedure CollectNTFwd; overload;
    procedure CollectForwards(Fwds: TForwardDict; hModReal, hModScan: HMODULE); overload;
    procedure GatherModuleExportsFromRemoteProcess(M: PRemoteModule);
    procedure TakeModuleSnapshot;
    function GetLocalProcAddr(hModule: HMODULE; ProcName: PAnsiChar): Pointer;
    function RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
  public
    constructor Create(const AProcess: TProcessInformation; AImageBase, AOEP: UIntPtr);
    destructor Destroy; override;

    function Process: TPEHeader;
    procedure DumpToFile(const FileName: string; PE: TPEHeader);

    function DetermineIATSize(IAT: PByte): UInt32;
    function IsAPIAddress(Address: NativeUInt): Boolean;

    property IAT: NativeUInt read FIAT write FIAT; // Virtual address of IAT in target
  end;

  TDumperDotnet = class
  private
    FProcess: TProcessInformation;
    FImageBase: UIntPtr;
  public
    constructor Create(const AProcess: TProcessInformation; AImageBase: UIntPtr);

    procedure DumpToFile(const FileName: string);
  end;

implementation

{ TDumper }

constructor TDumper.Create(const AProcess: TProcessInformation; AImageBase, AOEP: UIntPtr);
begin
  FProcess := AProcess;
  FOEP := AOEP;
  FImageBase := AImageBase;

  if Win32MajorVersion > 5 then
  begin
    FUsrPath := ExtractFilePath(ParamStr(0)) + 'mmusr32.dll';
    CopyFile('C:\Windows\system32\user32.dll', PChar(FUsrPath), False);
    FHUsr := LoadLibraryEx(PChar(FUsrPath), 0, $20) - 2;
  end;

  FForwards := TForwardDict.Create(32);
  FForwardsType2 := TForwardDict.Create(16);
  FForwardsOle32 := TForwardDict.Create(32);
  FForwardsNetapi32 := TForwardDict.Create(32);
  FForwardsCrypt32 := TForwardDict.Create(16);
  FForwardsDbghelp := TForwardDict.Create(16);
  FForwardsKernelbase := TForwardDict.Create(16);
  CollectNTFwd;
end;

destructor TDumper.Destroy;
var
  RM: PRemoteModule;
begin
  FForwards.Free;
  FForwardsType2.Free;
  FForwardsOle32.Free;
  FForwardsNetapi32.Free;
  FForwardsCrypt32.Free;
  FForwardsDbghelp.Free;
  FForwardsKernelbase.Free;

  if FAllModules <> nil then
  begin
    for RM in FAllModules do
    begin
      RM.ExportTbl.Free;
      Dispose(RM);
    end;
    FAllModules.Free;
  end;

  if FIATImage <> nil then
    FreeMem(FIATImage);

  if FHUsr <> 0 then
  begin
    FreeLibrary(FHUsr + 2);
    Windows.DeleteFile(PChar(FUsrPath));
  end;

  inherited;
end;

procedure TDumper.CollectNTFwd;
var
  hNetapi, hSrvcli, hCrypt32, hDpapi, hDbghelp, hDbgcore: HMODULE;
begin
  CollectForwards(FForwards, GetModuleHandle(kernel32), 0);
  if FHUsr <> 0 then
    CollectForwards(FForwardsType2, GetModuleHandle(user32), FHUsr);
  CollectForwards(FForwardsOle32, GetModuleHandle('ole32.dll'), 0);

  hNetapi := LoadLibrary('netapi32.dll');
  hSrvcli := LoadLibrary('srvcli.dll'); // Required for CollectForwards
  CollectForwards(FForwardsNetapi32, hNetapi, 0);
  FreeLibrary(hSrvcli);
  FreeLibrary(hNetapi);

  if Win32MajorVersion >= 6 then
  begin
    hCrypt32 := LoadLibrary('crypt32.dll');
    hDpapi := LoadLibrary('dpapi.dll'); // Required for CollectForwards
    CollectForwards(FForwardsCrypt32, hCrypt32, 0);
    FreeLibrary(hCrypt32);
    FreeLibrary(hDpapi);
  end;

  hDbghelp := LoadLibrary('dbghelp.dll');
  hDbgcore := LoadLibrary('dbgcore.dll'); // Required for CollectForwards
  CollectForwards(FForwardsDbghelp, hDbghelp, 0);
  FreeLibrary(hDbghelp);
  FreeLibrary(hDbgcore);

  if GetModuleHandle('kernelbase.dll') <> 0 then
    CollectForwards(FForwardsKernelbase, GetModuleHandle('kernelbase.dll'), 0);
end;

procedure TDumper.CollectForwards(Fwds: TForwardDict; hModReal, hModScan: HMODULE);
var
  ModScan: PByte;
  ExpDir: PImageExportDirectory;
  i, DotPos: Integer;
  a: PCardinal;
  Fwd: PAnsiChar;
  hMod: HMODULE;
  ProcAddr: Pointer;
begin
  if hModScan = 0 then
    hModScan := hModReal;
  ModScan := Pointer(hModScan);
  ExpDir := Pointer(ModScan + PImageNTHeaders(ModScan + PImageDosHeader(ModScan)._lfanew).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  a := PCardinal(ModScan + ExpDir.AddressOfFunctions);
  for i := 0 to ExpDir.NumberOfFunctions - 1 do
  begin
    Fwd := PAnsiChar(ModScan + a^); // e.g. NTDLL.RtlAllocateHeap
    DotPos := Pos(AnsiString('.'), Fwd);
    if (Length(Fwd) in [10..90]) and (((DotPos > 0) and (DotPos < 15)) or (Pos(AnsiString('api-ms-win'), Fwd) > 0)) and (Pos(AnsiString('.#'), Fwd) = 0) then
    begin
      hMod := GetModuleHandleA(PAnsiChar(Copy(Fwd, 1, DotPos - 1)));
      if hMod > 0 then
      begin
        // Not using the normal GetProcAddress because it can return apphelp hooks (e.g., CoCreateInstance when running as admin)
        ProcAddr := GetLocalProcAddr(hMod, PAnsiChar(Copy(Fwd, DotPos + 1, 50)));
        if ProcAddr <> nil then
          Fwds.AddOrSetValue(ProcAddr, PByte(hModReal) + a^);
        //Log(ltInfo, Format('%s @ %p', [PAnsiChar(Copy(Fwd, DotPos + 1, 50)), ProcAddr]));
      end
      //else
      //  Log(ltFatal, Format('Forward target not loaded: %s', [string(AnsiString(PAnsiChar(Copy(Fwd, 1, DotPos - 1))))]));
    end;
    Inc(a);
  end;
end;

procedure TDumper.DumpToFile(const FileName: string; PE: TPEHeader);
var
  FS: TFileStream;
  Buf: PByte;
  i: Integer;
  Size, Delta, IATRawOffset: Cardinal;
begin
  FS := TFileStream.Create(FileName, fmCreate);
  try
    Size := PE.DumpSize;
    GetMem(Buf, Size);
    if not RPM(FImageBase, Buf, Size) then
      raise Exception.Create('DumpToFile RPM failed');

    IATRawOffset := FIAT - FImageBase;
    // TrimHugeSections may adjust IATRawOffset depending on what is trimmed.
    Delta := PE.TrimHugeSections(Buf, IATRawOffset);
    Dec(Size, Delta);
    FS.Write(Buf^, Size);
    FreeMem(Buf);

    for i := PE.NTHeaders.FileHeader.NumberOfSections to High(PE.Sections) do
    begin
      FS.Write(PE.Sections[i].Data^, PE.Sections[i].Header.SizeOfRawData);
    end;
    PE.NTHeaders.FileHeader.NumberOfSections := Length(PE.Sections);
    PE.NTHeaders.OptionalHeader.AddressOfEntryPoint := FOEP - FImageBase;

    if (PE.NTHeaders.OptionalHeader.DllCharacteristics and $40) <> 0 then
    begin
      Log(ltInfo, 'Executable is ASLR-aware - disabling the flag in the dump');
      PE.NTHeaders.OptionalHeader.DllCharacteristics := PE.NTHeaders.OptionalHeader.DllCharacteristics and not $40;
    end;

    PE.SaveToStream(FS);

    FS.Seek(IATRawOffset, soBeginning);
    FS.Write(FIATImage^, FIATImageSize);
  finally
    FS.Free;
  end;
end;

{$POINTERMATH ON}

function TDumper.DetermineIATSize(IAT: PByte): UInt32;
var
  LastValidOffset, i: UInt32;
begin
  LastValidOffset := 0;
  i := 0;
  while (i < MAX_IAT_SIZE) and ((LastValidOffset = 0) or (i < LastValidOffset + $100)) do
  begin
    if IsAPIAddress(PNativeUInt(IAT + i)^) then
      LastValidOffset := i;

    Inc(i, SizeOf(Pointer));
  end;

  Result := LastValidOffset + SizeOf(Pointer);
end;

function TDumper.Process: TPEHeader;
var
  IAT: PByte;
  i, j: Integer;
  IATSize, Diff: Cardinal;
  PE: TPEHeader;
  a: ^PByte;
  Fwd: Pointer;
  Thunks: TList<TImportThunk>;
  Thunk: TImportThunk;
  NeedNewThunk, Found: Boolean;
  RM: PRemoteModule;
  s: AnsiString;
  OrdIndex: Cardinal;
  Section, Strs, RangeChecker: PByte;
  Descriptors: PImageImportDescriptor;
  ImportSect: PPESection;
begin
  if FIAT = 0 then
    raise Exception.Create('Must set IAT before calling Process()');

  // Read header from memory
  GetMem(Section, $1000);
  RPM(FImageBase, Section, $1000);
  PE := TPEHeader.Create(Section);
  PE.Sanitize;
  FreeMem(Section);

  GetMem(IAT, MAX_IAT_SIZE);
  RPM(FIAT, IAT, MAX_IAT_SIZE);

  IATSize := DetermineIATSize(IAT);
  Log(ltInfo, Format('Determined IAT size: %X', [IATSize]));

  with PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] do
  begin
    VirtualAddress := FIAT - FImageBase;
    Size := IATSize + SizeOf(Pointer);
  end;

  if FAllModules = nil then
    TakeModuleSnapshot;

  Thunks := TObjectList<TImportThunk>.Create;
  a := Pointer(IAT);
  NeedNewThunk := False; // whether there's an address "gap" (example: k32-api, 0, k32-api)
  for i := 0 to IATSize div SizeOf(Pointer) - 1 do
  begin
    //Log(ltInfo, IntToHex(UIntPtr(a) - UIntPtr(IAT) + FIAT, 8) + ' -> ' + IntToHex(UIntPtr(a^), 8));
    // Type 2: a^ is correct for export lookup, but need to look in different module! (ntdll --> user32)
    if FForwardsType2.TryGetValue(a^, Fwd) then
    begin
      {$IFDEF CPUX64}a^ := Fwd;{$ENDIF}
      RangeChecker := Fwd;
    end
    else
    begin
      // Some kernel32 functions are forwarded to ntdll - restore the original address
      if FForwards.TryGetValue(a^, Fwd) then
        a^ := Fwd
      else if FForwardsOle32.TryGetValue(a^, Fwd) then
        a^ := Fwd
      else if FForwardsNetapi32.TryGetValue(a^, Fwd) then
        a^ := Fwd
      else if FForwardsCrypt32.TryGetValue(a^, Fwd) then
        a^ := Fwd
      else if FForwardsDbghelp.TryGetValue(a^, Fwd) then
        a^ := Fwd
      else if FForwardsKernelbase.TryGetValue(a^, Fwd) then
        a^ := Fwd;
      RangeChecker := a^;
    end;
    //Log(ltInfo, ' -> ' + IntToHex(UIntPtr(a^), 8));

    Found := False;
    for RM in FAllModules do
      if (RangeChecker > RM.Base) and (RangeChecker < RM.EndOff) then
      begin
        if RM.ExportTbl = nil then
          GatherModuleExportsFromRemoteProcess(RM);

        if RM.ExportTbl.ContainsKey(a^) then
        begin
          if (Thunks.Count = 0) or (Thunks.Last.Name <> RM.Name) or NeedNewThunk then
          begin
            Thunks.Add(TImportThunk.Create(RM));
            NeedNewThunk := False; // reset
          end;

          Found := True;
          //Log(ltInfo, 'IAT ' + IntToHex(UIntPtr(a) - UIntPtr(IAT) + FIAT, 8) + ' -> API ' + IntToHex(UIntPtr(a^), 8) + ' belongs to ' + RM.Name);
          Thunks.Last.Addresses.Add(PPointer(a))
        end
        else
          Log(ltFatal, 'IAT ' + IntToHex(UIntPtr(a) - UIntPtr(IAT) + FIAT, 8) + ' -> API ' + IntToHex(UIntPtr(a^), 8) + ' not in export table of ' + RM.Name + ' (likely a bogus entry)');

        Break;
      end;

    if not Found then
      NeedNewThunk := True;

    Inc(a);
  end;

  ImportSect := PE.CreateSection('.import', $1000);

  Section := AllocMem(ImportSect.Header.SizeOfRawData);
  Pointer(Descriptors) := Section; // Map the Descriptors array to the start of the section
  Strs := Section + (Thunks.Count + 1) * SizeOf(TImageImportDescriptor); // Last descriptor is empty

  i := 0;
  for Thunk in Thunks do
  begin
    Descriptors[i].FirstThunk := (FIAT - FImageBase) + UIntPtr(Thunk.Addresses.First) - UIntPtr(IAT);
    Descriptors[i].Name := PE.ConvertOffsetToRVAVector(ImportSect.Header.PointerToRawData + Cardinal(Strs - Section));
    Inc(i);
    s := AnsiString(Thunk.Name);
    Move(s[1], Strs^, Length(s));
    Inc(Strs, Length(s) + 1);
    RM := Thunk.Module;
    Log(ltInfo, 'Thunk ' + Thunk.Name + ' - first import: ' + RM.ExportTbl[Thunk.Addresses.First^]);
    for j := 0 to Thunk.Addresses.Count - 1 do
    begin
      s := AnsiString(RM.ExportTbl[Thunk.Addresses[j]^]);
      if s[1] = '#' then
      begin
        OrdIndex := StrToInt(Copy(string(s), 2, 5));
        Thunk.Addresses[j]^ := Pointer(IMAGE_ORDINAL_FLAG or OrdIndex);
        Continue;
      end;

      Inc(Strs, 2); // Hint
      // Set the address in the IAT to this string entry
      Thunk.Addresses[j]^ := Pointer(PE.ConvertOffsetToRVAVector(ImportSect.Header.PointerToRawData + Cardinal(Strs - 2 - Section)));
      Move(s[1], Strs^, Length(s));
      Inc(Strs, Length(s) + 1);

      if Strs > Section + ImportSect.Header.SizeOfRawData - $100 then
      begin
        Inc(ImportSect.Header.SizeOfRawData, $1000);
        Inc(ImportSect.Header.Misc.VirtualSize, $1000);
        Inc(PE.NTHeaders.OptionalHeader.SizeOfImage, $1000);
        Diff := Strs - Section;
        ReallocMem(Section, ImportSect.Header.SizeOfRawData);
        FillChar((Section + ImportSect.Header.SizeOfRawData - $1000)^, $1000, 0);
        Strs := Section + Diff;
        Pointer(Descriptors) := Section;
        //Log(ltInfo, 'Increased import section size to ' + IntToHex(ImportSect.Header.SizeOfRawData, 4));
      end;
    end;
  end;

  ImportSect.Data := Section;
  with PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] do
  begin
    VirtualAddress := ImportSect.Header.VirtualAddress;
    Size := Thunks.Count * SizeOf(TImageImportDescriptor);
  end;

  Thunks.Free;

  FIATImage := IAT;
  FIATImageSize := IATSize;

  Result := PE;
end;

procedure TDumper.GatherModuleExportsFromRemoteProcess(M: PRemoteModule);
var
  Head: PByte;
  Exp: PImageExportDirectory;
  Off: PByte;
  a, n: PCardinal;
  o: PWord;
  i: Integer;
  Named: array of Boolean;
  FuncIndex: Cardinal;
begin
  M.ExportTbl := TExportTable.Create;
  GetMem(Head, $1000);
  RPM(NativeUInt(M.Base), Head, $1000);
  with PImageNtHeaders(Head + PImageDosHeader(Head)._lfanew).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] do
  begin
    GetMem(Exp, Size);
    RPM(NativeUInt(M.Base + VirtualAddress), Exp, Size);
    Off := PByte(Exp) - VirtualAddress;
  end;
  FreeMem(Head);

  Pointer(a) := Off + Exp.AddressOfFunctions;
  Pointer(n) := Off + Exp.AddressOfNames;
  Pointer(o) := Off + Exp.AddressOfNameOrdinals;

  SetLength(Named, Exp.NumberOfFunctions);
  FillChar(Named[0], Length(Named) * SizeOf(Boolean), 0);

  for i := 0 to Exp.NumberOfNames - 1 do
  begin
    FuncIndex := o[i];
    Named[FuncIndex] := True;
    M.ExportTbl.AddOrSetValue(M.Base + a[FuncIndex], string(AnsiString(PAnsiChar(Off + n[i]))));
  end;
  for i := 0 to Exp.NumberOfFunctions - 1 do
  begin
    if not Named[i] then
    begin
      FuncIndex := Exp.Base + UInt32(i);
      M.ExportTbl.AddOrSetValue(M.Base + a[i], '#' + IntToStr(FuncIndex));
    end;
  end;

  FreeMem(Exp);
end;

function TDumper.GetLocalProcAddr(hModule: HMODULE; ProcName: PAnsiChar): Pointer;
var
  Exp: PImageExportDirectory;
  Off: PByte;
  a, n: PCardinal;
  o: PWord;
  i: Integer;
begin
  with PImageNtHeaders(hModule + Cardinal(PImageDosHeader(hModule)._lfanew)).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] do
  begin
    Exp := Pointer(hModule + VirtualAddress);
    Off := PByte(Exp) - VirtualAddress;
  end;

  Pointer(a) := Off + Exp.AddressOfFunctions;
  Pointer(n) := Off + Exp.AddressOfNames;
  Pointer(o) := Off + Exp.AddressOfNameOrdinals;
  for i := 0 to Exp.NumberOfNames - 1 do
    if AnsiStrComp(PAnsiChar(Off + n[i]), ProcName) = 0 then
      Exit(Pointer(hModule + a[o[i]]));

  Result := nil;
end;

function TDumper.IsAPIAddress(Address: NativeUInt): Boolean;
var
  RM: PRemoteModule;
begin
  if FAllModules = nil then
    TakeModuleSnapshot;

  for RM in FAllModules do
    if (Address >= NativeUInt(RM.Base)) and (Address < NativeUInt(RM.EndOff)) then
    begin
      if RM.ExportTbl = nil then
        GatherModuleExportsFromRemoteProcess(RM);

      Exit(RM.ExportTbl.ContainsKey(Pointer(Address)));
    end;

  Result := False;
end;

procedure TDumper.TakeModuleSnapshot;
var
  hSnap: THandle;
  ME: TModuleEntry32;
  RM: PRemoteModule;
begin
  FAllModules := TList<PRemoteModule>.Create;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, FProcess.dwProcessId);
  ME.dwSize := SizeOf(TModuleEntry32);
  if not Module32First(hSnap, ME) then
    raise Exception.Create('Module32First');
  repeat
    if ME.hModule <> FImageBase then
    begin
      //Log(ltInfo, IntToHex(ME.hModule, 8) + ' : ' + IntToHex(ME.modBaseSize, 4) + ' : ' + string(ME.szModule));
      New(RM);
      RM.Base := ME.modBaseAddr;
      RM.EndOff := ME.modBaseAddr + ME.modBaseSize;
      RM.Name := LowerCase(ME.szModule);
      RM.ExportTbl := nil;
      FAllModules.Add(RM);
    end;
  until not Module32Next(hSnap, ME);
  CloseHandle(hSnap);
end;

function TDumper.RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
begin
  Result := ReadProcessMemory(FProcess.hProcess, Pointer(Address), Buf, BufSize, BufSize);
  if not Result then
    Log(ltFatal, 'RPM failed');
end;

{ TDumperDotnet }

constructor TDumperDotnet.Create(const AProcess: TProcessInformation; AImageBase: UIntPtr);
begin
  FProcess := AProcess;
  FImageBase := AImageBase;
end;

procedure TDumperDotnet.DumpToFile(const FileName: string);
var
  FS: TFileStream;
  Header: array[0..$FFF] of Byte;
  PE: TPEHeader;
  Buf, Ptr: PByte;
  Size, PhysicalSize, ImageSize, Done: DWORD;
  NumRead: UIntPtr;
  Mbi: TMemoryBasicInformation;
begin
  // Dumping Themida .NET binaries appears to be quite simple because
  // no special imports processing is required.
  NumRead := 0;
  if not ReadProcessMemory(FProcess.hProcess, Pointer(FImageBase), @Header, $1000, NumRead) then
    raise Exception.Create('DumpToFile header RPM failed');

  PE := TPEHeader.Create(@Header);
  with PE.Sections[PE.NTHeaders.FileHeader.NumberOfSections - 1] do
    Size := Header.VirtualAddress + Header.Misc.VirtualSize;

  FS := TFileStream.Create(FileName, fmCreate);
  GetMem(Buf, Size);
  try
    PhysicalSize := Size;
    PE.FileAlign(PhysicalSize);
    ImageSize := PhysicalSize;
    PE.SectionAlign(ImageSize);
    PE.NTHeaders.OptionalHeader.SizeOfImage := ImageSize;
    PE.Sections[0].Rename('.text');

    Log(ltInfo, Format('Output has %d sections, determined size to be 0x%X', [PE.NTHeaders.FileHeader.NumberOfSections, Size]));

    Ptr := PByte(FImageBase);
    Done := 0;
    Mbi.RegionSize := $1000;
    while Done < Size do
    begin
      if VirtualQueryEx(FProcess.hProcess, Ptr, Mbi, SizeOf(Mbi)) = 0 then
        raise Exception.CreateFmt('VirtualQueryEx failed at %p', [Ptr]);
      if Mbi.RegionSize = 0 then
        raise Exception.CreateFmt('VirtualQueryEx returned a zero region at %p', [Ptr]); // Idk if/why it would do this but we wouldn't make any progress then

      if Mbi.State = MEM_COMMIT then
      begin
        NumRead := 0;
        if not ReadProcessMemory(FProcess.hProcess, Ptr, Buf + Done, Min(Size - Done, Mbi.RegionSize), NumRead) then
          raise Exception.Create('DumpToFile RPM failed');
      end
      else if Mbi.State = MEM_RESERVE then
      begin
        // We could mess with the section addresses and leave this chunk out of the physical file, but eh...
        FillChar((Buf + Done)^, Min(Size - Done, Mbi.RegionSize), 0);
      end
      else
        raise Exception.CreateFmt('Got unexpected region state %X at %p', [Mbi.State, Ptr]);

      Inc(Done, Mbi.RegionSize);
      Inc(Ptr, Mbi.RegionSize);
    end;

    FS.Write(Buf^, Size);
    if Size < PhysicalSize then
    begin
      // Pad to file alignment
      ReallocMem(Buf, PhysicalSize - Size);
      FillChar(Buf^, PhysicalSize - Size, 0);
      FS.Write(Buf^, PhysicalSize - Size);
    end;

    PE.SaveToStream(FS);
  finally
    FreeMem(Buf);
    PE.Free;
    FS.Free;
  end;
end;

{ TImportThunk }

constructor TImportThunk.Create(RM: PRemoteModule);
begin
  Module := RM;
  Name := RM.Name;
  Addresses := TList<PPointer>.Create;
end;

destructor TImportThunk.Destroy;
begin
  Addresses.Free;

  inherited;
end;

end.
