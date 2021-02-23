#include "Tests/LinuxSyscalls/Syscalls.h"
#include "Tests/LinuxSyscalls/x32/Syscalls.h"

#include <sys/mount.h>
#include <unistd.h>

#define GET_PATH(pathname) (pathname ? FEX::HLE::_SyscallHandler->FM.GetEmulatedPath(pathname).c_str() : nullptr)

namespace FEX::HLE::x32 {
  void RegisterFS() {
    REGISTER_SYSCALL_IMPL_X32(umount, [](FEXCore::Core::InternalThreadState *Thread, const char *target) -> uint64_t {
      uint64_t Result = ::umount(GET_PATH(target));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL_X32(ftruncate64, [](FEXCore::Core::InternalThreadState *Thread, int fd, uint32_t offset_low, uint32_t offset_high) -> uint64_t {
      uint64_t Offset = offset_high;
      Offset <<= 32;
      Offset |= offset_low;
      uint64_t Result = ::ftruncate(fd, Offset);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL_X32(sigprocmask, [](FEXCore::Core::InternalThreadState *Thread, int how, const uint64_t *set, uint64_t *oldset, size_t sigsetsize) -> uint64_t {
      return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSigProcMask(how, set, oldset);
    });
  }
}
