/*
$info$
tags: backend|x86-64
desc: relocation logic of the x86-64 splatter backend
$end_info$
*/
#include "FEXCore/Utils/LogManager.h"
#include "Interface/Context/Context.h"
#include "Interface/Core/JIT/x86_64/JITClass.h"
#include "Interface/HLE/Thunks/Thunks.h"
#include "Interface/Core/ObjectCache/Relocations.h"
#include "Interface/ObjCache.h"
#include "xbyak/xbyak.h"

#define AOTLOG(...)
//#define AOTLOG LogMan::Msg::DFmt

namespace FEXCore::CPU {
uint64_t X86JITCore::GetNamedSymbolLiteral(FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op) {
  switch (Op) {
    case FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER:
      return ThreadState->CurrentFrame->Pointers.Common.ExitFunctionLinker;
    break;
    default:
      ERROR_AND_DIE_FMT("Unknown named symbol literal: {}", static_cast<uint32_t>(Op));
    break;
  }
  return ~0ULL;

}

void X86JITCore::InsertNamedThunkRelocation(Xbyak::Reg Reg, const IR::SHA256Sum &Sum) {
  Relocation MoveABI{};
  MoveABI.NamedThunkMove.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE;
  // Offset is the offset from the entrypoint of the block
  auto CurrentCursor = getSize();
  MoveABI.NamedThunkMove.Offset = CurrentCursor - CursorEntry;
  MoveABI.NamedThunkMove.Symbol = Sum;
  MoveABI.NamedThunkMove.RegisterIndex = Reg.getIdx();

  uint64_t Pointer = reinterpret_cast<uint64_t>(CTX->ThunkHandler->LookupThunk(Sum));

  LoadConstantWithPadding(Reg, Pointer);
  Relocations.emplace_back(MoveABI);
}

void X86JITCore::LoadConstantWithPadding(Xbyak::Reg Reg, uint64_t Constant) {
  // The maximum size a move constant can be in bytes
  // Need to NOP pad to this size to ensure backpatching is always the same size
  // Calculated as:
  // [Rex]
  // [Mov op]
  // [8 byte constant]
  //
  // All other move types are smaller than this. xbyak will use a NOP slide which is quite quick
  constexpr static size_t MAX_MOVE_SIZE = 10;
  auto StartingOffset = getSize();
  mov(Reg, Constant);
  auto MoveSize = getSize() - StartingOffset;
  auto NOPPadSize = MAX_MOVE_SIZE - MoveSize;
  nop(NOPPadSize);
}

X86JITCore::RelocatedLiteralPair X86JITCore::InsertNamedSymbolLiteral(FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op) {
  RelocatedLiteralPair Lit {
    .MoveABI = {
      .NamedSymbolLiteral = {
        .Header = {
          .Type = FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL,
        },
        .Symbol = Op,
        .Offset = 0,
      },
    },
  };
  return Lit;
}

X86JITCore::RelocatedLiteralPair X86JITCore::InsertGuestRIPLiteral(const uint64_t GuestRip) {
  RelocatedLiteralPair Lit {
    .MoveABI = {
      .GuestRIPMove = {
        .Header = {
          .Type = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL,
        },
        .Offset = 0,
        .GuestEntryOffset = GuestRip - Entry,
      },
    },
  };
  return Lit;
}

void X86JITCore::PlaceRelocatedLiteral(RelocatedLiteralPair &Lit) {
  uint64_t Value;

  L(Lit.Offset);

  switch (Lit.MoveABI.Header.Type) {
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL:
      Value = GetNamedSymbolLiteral(Lit.MoveABI.NamedSymbolLiteral.Symbol);
      Lit.MoveABI.NamedSymbolLiteral.Offset = getSize() - CursorEntry;
      break;

    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL:
      Value = Lit.MoveABI.GuestRIPLiteral.GuestEntryOffset + Entry;
      Lit.MoveABI.GuestRIPLiteral.Offset = getSize() - CursorEntry;
      break;
    default:
      ERROR_AND_DIE_FMT("PlaceRelocatedLiteral: Invalid value in Lit.MoveABI.Header.Type");
  }

  dq(Value);

  Relocations.emplace_back(Lit.MoveABI);
}


void X86JITCore::InsertGuestRIPMove(Xbyak::Reg Reg, const uint64_t GuestRip) {
  Relocation MoveABI{};
  MoveABI.GuestRIPMove.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE;

  // Offset is the offset from the entrypoint of the block
  auto CurrentCursor = getSize();
  MoveABI.GuestRIPMove.Offset = CurrentCursor - CursorEntry;
  MoveABI.GuestRIPMove.GuestEntryOffset = GuestRip - Entry;
  MoveABI.GuestRIPMove.RegisterIndex = Reg.getIdx();

  //if (CTX->Config.CacheObjectCodeCompilation()) {
    LoadConstantWithPadding(Reg, GuestRip);
  //}
  //else {
//    mov(Reg, GuestRip);
//  }

  Relocations.emplace_back(MoveABI);
}

void *X86JITCore::RelocateJITObjectCode(uint64_t Entry, const Obj::FragmentHostCode *const HostCode, const Obj::FragmentRelocations *const Relocations) {
  AOTLOG("Relocating RIP 0x{:x}", Entry);

  if ((getSize() + HostCode->Bytes) > CurrentCodeBuffer->Size) {
    ThreadState->CTX->ClearCodeCache(ThreadState);
  }

  auto CursorBegin = getSize();
	auto HostEntry = getCurr<uint64_t>();
  AOTLOG("RIP Entry: disas 0x{:x},+{}", (uintptr_t)HostEntry, HostCode->Bytes);

  // Forward the cursor
  setSize(CursorBegin + HostCode->Bytes);

  memcpy(reinterpret_cast<void*>(HostEntry), HostCode->Code, HostCode->Bytes);

  // Relocation apply messes with the cursor
  // Save the cursor and restore at the end
  auto NewCursor = getSize();
  bool Result = ApplyRelocations(Entry, HostEntry, CursorBegin, Relocations);

  if (!Result) {
    // Reset cursor to the start
    setSize(CursorBegin);
    return nullptr;
  }

  // We've moved the cursor around with relocations. Move it back to where we were before relocations
  setSize(NewCursor);

  ready();

  this->IR = nullptr;

  //AOTLOG("\tRelocated JIT at [0x{:x}, 0x{:x}): RIP 0x{:x}", (uint64_t)HostEntry, CodeEnd, Entry);
  return reinterpret_cast<void*>(HostEntry);
}

bool X86JITCore::ApplyRelocations(uint64_t GuestEntry, uint64_t CodeEntry, uint64_t CursorEntry, const Obj::FragmentRelocations *const Relocations) {
  //size_t DataIndex{};
  for (size_t j = 0; j < Relocations->Count; ++j) {
    //const FEXCore::CPU::Relocation *Reloc = reinterpret_cast<const FEXCore::CPU::Relocation *>(&EntryRelocations[DataIndex]);
    auto Reloc = Relocations->Relocations + j;
    //LOGMAN_THROW_A_FMT((DataIndex % alignof(Relocation)) == 0, "Alignment of relocation wasn't adhered to");
  
    switch (Reloc->Header.Type) {
      case FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL: {
        uint64_t Pointer = GetNamedSymbolLiteral(Reloc->NamedSymbolLiteral.Symbol);
        // Relocation occurs at the cursorEntry + offset relative to that cursor.
        setSize(CursorEntry + Reloc->NamedSymbolLiteral.Offset);

        // Place the pointer
        dq(Pointer);

        //DataIndex += sizeof(Reloc->NamedSymbolLiteral);
        break;
      }
      case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
        uint64_t Pointer = GuestEntry + Reloc->GuestRIPMove.GuestEntryOffset;

        setSize(CursorEntry + Reloc->GuestRIPMove.Offset);
        dq(Pointer);
        //DataIndex += sizeof(Reloc->GuestRIPMove);
        break;
      }
      case FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE: {
        uint64_t Pointer = reinterpret_cast<uint64_t>(CTX->ThunkHandler->LookupThunk(Reloc->NamedThunkMove.Symbol));
        if (Pointer == ~0ULL) {
          return false;
        }

        // Relocation occurs at the cursorEntry + offset relative to that cursor.
        setSize(CursorEntry + Reloc->NamedThunkMove.Offset);
        LoadConstantWithPadding(Xbyak::Reg64(Reloc->NamedThunkMove.RegisterIndex), Pointer);
        //DataIndex += sizeof(Reloc->NamedThunkMove);
        break;
      }
      case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE: {
        uint64_t Pointer = GuestEntry + Reloc->GuestRIPMove.GuestEntryOffset;

        // Relocation occurs at the cursorEntry + offset relative to that cursor.
        setSize(CursorEntry + Reloc->GuestRIPMove.Offset);
        LoadConstantWithPadding(Xbyak::Reg64(Reloc->GuestRIPMove.RegisterIndex), Pointer);
        //DataIndex += sizeof(Reloc->GuestRIPMove);
        break;
      }
    }
  }

  return true;
}
}

