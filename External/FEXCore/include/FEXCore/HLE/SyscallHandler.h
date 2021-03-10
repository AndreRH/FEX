#pragma once
#include <cstdint>
#include <string>

namespace FEXCore::Context {
  struct Context;
}

namespace FEXCore::Core {
  struct InternalThreadState;
}

namespace FEXCore::HLE {
  struct SyscallArguments {
    static constexpr std::size_t MAX_ARGS = 7;
    uint64_t Argument[MAX_ARGS];
  };

  struct SyscallABI {
    // Expectation is that the backend will be aware of how to modify the arguments based on numbering
    // Only GPRs expected
    uint8_t NumArgs;
    // If the syscall has a return then it should be stored in the ABI specific syscall register
    // Linux = RAX
    bool HasReturn;
  };

  enum class SyscallOSABI {
    OS_LINUX64,
    OS_LINUX32,
    OS_HANGOVER,
  };

  class SyscallHandler {
  public:
    virtual ~SyscallHandler() = default;

    virtual uint64_t HandleSyscall(FEXCore::Core::InternalThreadState *Thread, FEXCore::HLE::SyscallArguments *Args) = 0;
    virtual SyscallABI GetSyscallABI(uint64_t Syscall) = 0;

    SyscallOSABI GetOSABI() const { return OSABI; }

  protected:
    SyscallOSABI OSABI;
  };
}
