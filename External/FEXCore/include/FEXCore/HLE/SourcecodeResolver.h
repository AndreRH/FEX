#pragma once
#include <algorithm>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>

#include <fmt/format.h>

namespace FEXCore::HLE {

struct SourcecodeLineMapping {
  uintptr_t FileGuestBegin;
  uintptr_t FileGuestEnd;
  
  int LineNumber;
};

struct SourcecodeSymbolMapping {
  uintptr_t FileGuestBegin;
  uintptr_t FileGuestEnd;

  std::string Name;

  static std::string SymName(const SourcecodeSymbolMapping *Sym, const std::string &GuestFilename, uintptr_t HostEntry, uintptr_t FileBegin) {
    if (Sym) {
      auto SymOffset = FileBegin - Sym->FileGuestBegin;
      if (SymOffset) {
        return fmt::format("{}: {}+{} @{:x}", std::filesystem::path(GuestFilename).stem().string(), Sym->Name,
                              SymOffset, HostEntry);
      } else {
        return fmt::format("{}: {} @{:x}", std::filesystem::path(GuestFilename).stem().string(), Sym->Name,
                              HostEntry);
      }
    } else {
      return fmt::format("{}: +{} @{:x}", std::filesystem::path(GuestFilename).stem().string(), FileBegin,
                            HostEntry);
    }
  }
};

struct SourcecodeMap {
  std::string SourceFile;
  std::vector<SourcecodeLineMapping> SortedLineMappings;
  std::vector<SourcecodeSymbolMapping> SortedSymbolMappings;

  template<typename F>
  void IterateLineMappings(uintptr_t FileBegin, uintptr_t Size, const F &Callback) const {
    auto Begin = FileBegin;
    auto End = FileBegin + Size;

    auto Found = std::lower_bound(SortedLineMappings.cbegin(), SortedLineMappings.cend(), Begin, [](const auto &Range, const auto Position) {
      return Range.FileGuestEnd <= Position;
    });

    while (Found != SortedLineMappings.cend()) {
      if (Found->FileGuestBegin < End && Found->FileGuestEnd > Begin) {
        Callback(Found);
      } else {
        break;
      }
      Found++;
    }
  }

  const SourcecodeLineMapping *FindLineMapping(uintptr_t FileBegin) const {
    return Find(FileBegin, SortedLineMappings);
  }

  const SourcecodeSymbolMapping *FindSymbolMapping(uintptr_t FileBegin) const {
    return Find(FileBegin, SortedSymbolMappings);
  }
private:
  template<typename VecT>
  const typename VecT::value_type *Find(uintptr_t FileBegin, const VecT &SortedMappings) const {
    auto Found = std::lower_bound(SortedMappings.cbegin(), SortedMappings.cend(), FileBegin, [](const auto &Range, const auto Position) {
      return Range.FileGuestEnd <= Position;
    });

    if (Found != SortedMappings.end() && Found->FileGuestBegin <= FileBegin && Found->FileGuestEnd > FileBegin) {
      return &(*Found);
    } else {
      return {};
    }
  }
};

class SourcecodeResolver {
public:
  virtual std::unique_ptr<SourcecodeMap> GenerateMap(const std::string_view& GuestBinaryFile, const std::string_view& GuestBinaryFileId) = 0;
};
}
