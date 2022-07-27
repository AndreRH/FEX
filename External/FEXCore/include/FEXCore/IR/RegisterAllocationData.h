#pragma once
#include "IR.h"
#include <FEXCore/Utils/Allocator.h>
#include <cstring>

namespace FEXCore::IR {

union PhysicalRegister {
  uint8_t Raw;
  struct {
    uint8_t Reg: 5;
    uint8_t Class: 3;
  };

  bool operator==(const PhysicalRegister &Other) const {
    return Raw == Other.Raw;
  }

  PhysicalRegister(RegisterClassType Class, uint8_t Reg) : Reg(Reg), Class(Class.Val) { }

  static const PhysicalRegister Invalid() {
    return PhysicalRegister(InvalidClass, InvalidReg);
  }

  bool IsInvalid() const {
    return *this == Invalid();
  }
};

static_assert(sizeof(PhysicalRegister) == 1);

struct RegisterAllocationDataDeleter;

// This class is serialized, can't have any holes in the structure
// otherwise ASAN complains about reading uninitialized memory
class FEX_PACKED RegisterAllocationData {
  public:
    uint32_t SpillSlotCount {};
    uint32_t MapCount {};
    bool IsShared {false};
    PhysicalRegister Map[0];

    PhysicalRegister GetNodeRegister(NodeID Node) const {
      return Map[Node.Value];
    }
    uint32_t SpillSlots() const { return SpillSlotCount; }

    static size_t Size(uint32_t NodeCount) {
      return sizeof(RegisterAllocationData) + NodeCount * sizeof(Map[0]);
    }

    size_t Size() const {
      return Size(MapCount);
    }

    using UniquePtr = std::unique_ptr<FEXCore::IR::RegisterAllocationData, RegisterAllocationDataDeleter>;

    static UniquePtr Create(uint32_t NodeCount);

    UniquePtr CreateCopy() const;

    void Serialize(std::ostream& stream) const {
      stream.write((const char*)&SpillSlotCount, sizeof(SpillSlotCount));
      stream.write((const char*)&MapCount, sizeof(MapCount));
      // RAData (inline)
      // In file, IsShared is always set
      bool _IsShared = true;
      stream.write((const char*)&_IsShared, sizeof(IsShared));
      stream.write((const char*)&Map[0], sizeof(Map[0]) * MapCount);
    }

    void Serialize(uint8_t *ptr) const {
      memcpy(ptr, &SpillSlotCount, sizeof(SpillSlotCount)); ptr += sizeof(SpillSlotCount);
      memcpy(ptr, &MapCount, sizeof(MapCount)); ptr += sizeof(MapCount);
      // RAData (inline)
      // In file, IsShared is always set
      bool _IsShared = true;
      memcpy(ptr, &_IsShared, sizeof(_IsShared)); ptr += sizeof(_IsShared);
      memcpy(ptr, &Map[0], sizeof(Map[0]) * MapCount); ptr += sizeof(Map[0]) * MapCount;
    }
};

struct RegisterAllocationDataDeleter {
  void operator()(RegisterAllocationData* r) const {
    if (!r->IsShared) {
      FEXCore::Allocator::free(r);
    }
  }
};

inline auto RegisterAllocationData::Create(uint32_t NodeCount) -> UniquePtr {
  auto Ret = (RegisterAllocationData*)FEXCore::Allocator::malloc(Size(NodeCount));
  memset(&Ret->Map[0], PhysicalRegister::Invalid().Raw, NodeCount);
  Ret->MapCount = NodeCount;
  return UniquePtr { Ret };
}

inline auto RegisterAllocationData::CreateCopy() const -> UniquePtr {
  auto copy = (RegisterAllocationData*)FEXCore::Allocator::malloc(Size(MapCount));
  memcpy((void*)&copy->Map[0], (void*)&Map[0], MapCount * sizeof(Map[0]));
  copy->SpillSlotCount = SpillSlotCount;
  copy->MapCount = MapCount;
  copy->IsShared = IsShared;
  return UniquePtr { copy };
}

}
