#pragma once

#include <string.h>
#include "CodeCache.h"

#include <FEXCore/Core/CPURelocations.h>

namespace FEXCore {  
  constexpr static uint32_t OBJ_CACHE_VERSION = 0x0000'00001;
  constexpr static uint64_t OBJ_CACHE_INDEX_COOKIE = COOKIE_VERSION("FXOI", OBJ_CACHE_VERSION);
  constexpr static uint64_t OBJ_CACHE_DATA_COOKIE = COOKIE_VERSION("FXOD", OBJ_CACHE_VERSION);

    //const CodeSerializationData *Data;
    //const char *HostCode;
    //uint64_t NumRelocations;
    //const char *Relocations;

  struct ObjCacheFragment {
    uint64_t Bytes;
    uint8_t Code[0];
  };

  struct ObjCacheRelocations {
    size_t Count;
    FEXCore::CPU::Relocation Relocations[0];
  };

  struct ObjCacheEntry : CacheEntry {

    auto GetObjCacheFragment() const {
      return (const ObjCacheFragment *)&GetRangeData()[GuestRangeCount];
    }

    auto GetObjCacheFragment() {
      return (ObjCacheFragment *)&GetRangeData()[GuestRangeCount];
    }

    auto GetObjCacheRelocations() const {
      auto v = GetObjCacheFragment();
      
      return (const ObjCacheRelocations *)&v->Code[v->Bytes];
    }

    auto GetObjCacheRelocations() {
      auto v = GetObjCacheFragment();
      
      return (ObjCacheRelocations *)&v->Code[v->Bytes];
    }

    static uint64_t GetInlineSize(const void *HostCode, const size_t HostCodeBytes, const std::vector<FEXCore::CPU::Relocation> &Relocations) {
      return HostCodeBytes + Relocations.size() * sizeof(Relocations[0]);
    }

    static auto GetFiller(const void *HostCode, const size_t HostCodeBytes, const std::vector<FEXCore::CPU::Relocation> &Relocations) {
      return [HostCode, HostCodeBytes, &Relocations](auto *Entry) {
        auto ObjEntry = (ObjCacheEntry*)Entry;

        ObjEntry->GetObjCacheFragment()->Bytes = HostCodeBytes;
        memcpy(ObjEntry->GetObjCacheFragment()->Code, HostCode, HostCodeBytes);

        ObjEntry->GetObjCacheRelocations()->Count = Relocations.size();
        memcpy(ObjEntry->GetObjCacheRelocations()->Relocations, Relocations.data(), Relocations.size() * sizeof(*Relocations.data()));
      };
    }
  };
  
  struct ObjCacheResult {
    using CacheEntryType = ObjCacheEntry;

    ObjCacheResult(const ObjCacheEntry *const Entry) {
      Entry->toResult(this);

      HostCode = Entry->GetObjCacheFragment();
      RelocationData = Entry->GetObjCacheRelocations();
    }
    const std::pair<uint64_t, uint64_t> *RangeData;
    uint64_t RangeCount;
    const ObjCacheFragment *HostCode;
    const ObjCacheRelocations *RelocationData;
  };

  template <typename FDPairType>
  auto LoadObjCache(FDPairType CacheFDs) {
    return CodeCache::LoadFile(CacheFDs->IndexFD, CacheFDs->DataFD, OBJ_CACHE_INDEX_COOKIE, OBJ_CACHE_DATA_COOKIE);
  }

}