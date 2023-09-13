/*
$info$
category: glue ~ Logic that binds various parts together
meta: glue|driver ~ C interface for Hangover
tags: glue|driver
desc: Glues C to FEX
$end_info$
*/

#ifndef __MINGW32__

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "Hangover.h"

class DummySyscallHandler : public FEXCore::HLE::SyscallHandler {
public:
  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Args) override {
    return 0;
  }

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    return {0, false, 0 };
  }

  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState *Thread, uint64_t GuestAddr) override {
    return {0, 0};
  }
};

static fextl::unique_ptr<FEXCore::Context::Context> CTX;
DummySyscallHandler SyscallHandler;

extern "C" __attribute__((visibility ("default"))) void hangover_fex_init() {
  FEXCore::Config::Initialize();
  FEXCore::Config::ReloadMetaLayer();

  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS_INTERPRETER, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_TSOENABLED, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_MULTIBLOCK, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_X87REDUCEDPRECISION, "0");
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_BLOCKJITNAMING, "1");

  FEXCore::Context::InitializeStaticTables( FEXCore::Context::MODE_32BIT);

  CTX = FEXCore::Context::Context::CreateNewContext();
  CTX->SetSyscallHandler(&SyscallHandler);
  CTX->InitCore();
}

static thread_local FEXCore::Core::InternalThreadState *Thread;

static void LoadStateFromWinContext(FEXCore::Core::CPUState& State, uint64_t WowTeb, I386_CONTEXT* Context)
{
  // General register state

  State.gregs[FEXCore::X86State::REG_RAX] = Context->Eax;
  State.gregs[FEXCore::X86State::REG_RBX] = Context->Ebx;
  State.gregs[FEXCore::X86State::REG_RCX] = Context->Ecx;
  State.gregs[FEXCore::X86State::REG_RDX] = Context->Edx;
  State.gregs[FEXCore::X86State::REG_RSI] = Context->Esi;
  State.gregs[FEXCore::X86State::REG_RDI] = Context->Edi;
  State.gregs[FEXCore::X86State::REG_RBP] = Context->Ebp;
  State.gregs[FEXCore::X86State::REG_RSP] = Context->Esp;

  State.rip = Context->Eip;
  CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);

  State.es_idx = Context->SegEs & 0xFFFF;
  State.cs_idx = Context->SegCs & 0xFFFF;
  State.ss_idx = Context->SegSs & 0xFFFF;
  State.ds_idx = Context->SegDs & 0xFFFF;
  State.fs_idx = Context->SegFs & 0xFFFF;
  State.gs_idx = Context->SegGs & 0xFFFF;

  // The TEB is the only populated GDT entry by default
  State.SetGDTBase(&State.gdt[State.fs_idx >> 3], WowTeb);
  State.SetGDTLimit(&State.gdt[State.fs_idx >> 3], 0xF'FFFFU);
  State.fs_cached = WowTeb;
  State.es_cached = 0;
  State.cs_cached = 0;
  State.ss_cached = 0;
  State.ds_cached = 0;

  // Floating-point register state

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  memcpy(State.xmm.sse.data, XSave->XmmRegisters, sizeof(State.xmm.sse.data));
  memcpy(State.mm, XSave->FloatRegisters, sizeof(State.mm));

  State.FCW = XSave->ControlWord;
  State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (XSave->StatusWord >> 8) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (XSave->StatusWord >> 9) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (XSave->StatusWord >> 10) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (XSave->StatusWord >> 14) & 1;
  State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (XSave->StatusWord >> 11) & 0b111;
  State.AbridgedFTW = XSave->TagWord;
}

static void StoreWinContextFromState(FEXCore::Core::CPUState& State, I386_CONTEXT* Context)
{
  // General register state

  Context->Eax = State.gregs[FEXCore::X86State::REG_RAX];
  Context->Ebx = State.gregs[FEXCore::X86State::REG_RBX];
  Context->Ecx = State.gregs[FEXCore::X86State::REG_RCX];
  Context->Edx = State.gregs[FEXCore::X86State::REG_RDX];
  Context->Esi = State.gregs[FEXCore::X86State::REG_RSI];
  Context->Edi = State.gregs[FEXCore::X86State::REG_RDI];
  Context->Ebp = State.gregs[FEXCore::X86State::REG_RBP];
  Context->Esp = State.gregs[FEXCore::X86State::REG_RSP];

  Context->Eip = State.rip;
  Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);

  Context->SegEs = State.es_idx;
  Context->SegCs = State.cs_idx;
  Context->SegSs = State.ss_idx;
  Context->SegDs = State.ds_idx;
  Context->SegFs = State.fs_idx;
  Context->SegGs = State.gs_idx;

  // Floating-point register state

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  memcpy(XSave->XmmRegisters, State.xmm.sse.data, sizeof(State.xmm.sse.data));
  memcpy(XSave->FloatRegisters, State.mm, sizeof(State.mm));

  XSave->ControlWord = State.FCW;
  XSave->StatusWord =
    (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) |
    (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
    (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) |
    (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
    (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14);
  XSave->TagWord = State.AbridgedFTW;

  Context->FloatSave.ControlWord = XSave->ControlWord;
  Context->FloatSave.StatusWord = XSave->StatusWord;
  Context->FloatSave.TagWord = FEXCore::FPState::ConvertFromAbridgedFTW(XSave->StatusWord, State.mm, XSave->TagWord);
  Context->FloatSave.ErrorOffset = XSave->ErrorOffset;
  Context->FloatSave.ErrorSelector = XSave->ErrorSelector | (XSave->ErrorOpcode << 16);
  Context->FloatSave.DataOffset = XSave->DataOffset;
  Context->FloatSave.DataSelector = XSave->DataSelector;
  Context->FloatSave.Cr0NpxState = XSave->StatusWord | 0xffff0000;
}

extern "C" __attribute__((visibility ("default"))) void hangover_fex_run(void* WowTeb, I386_CONTEXT* Context)
{
  if (!Thread)
    Thread = CTX->CreateThread(0, 0, FEXCore::Context::Context::ManagedBy::FRONTEND);

  static constexpr uint32_t RequiredContextFlags = CONTEXT_I386_FULL | CONTEXT_I386_DEBUG_REGISTERS;

  if ((Context->ContextFlags & RequiredContextFlags) != RequiredContextFlags)
    fprintf(stderr, "Incomplete context!\n");

  LoadStateFromWinContext(Thread->CurrentFrame->State, (uint64_t)WowTeb, Context);

  CTX->ExecutionThread(Thread);

  StoreWinContextFromState(Thread->CurrentFrame->State, Context);
}

extern "C" __attribute__((visibility ("default"))) void hangover_fex_invalidate_code_range(uint64_t Start, uint64_t Length)
{
  if (!CTX)
    return;

  CTX->InvalidateGuestCodeRange(Thread, Start, Length);
}

#endif
