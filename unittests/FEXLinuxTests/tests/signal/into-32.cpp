#include <atomic>
#include <signal.h>

// arch: x86_32

std::atomic<bool> CorrectFaultData{false};
static void handler(int signal, siginfo_t *siginfo, void* context) {
  ucontext_t *_context = (ucontext_t*)context;

  if (signal != SIGSEGV) {
    return;
  }

  if (siginfo->si_addr != nullptr) {
    return;
  }

  if (_context->uc_mcontext.gregs[REG_TRAPNO] != 4) {
    return;
  }

  CorrectFaultData = true;
}

int main() {
  struct sigaction act{};
  act.sa_sigaction = handler;
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &act, nullptr);

  __asm volatile(R"(
  mov $0x7f, %%eax;
  incb %%al;
  into;
  )" ::: "eax");

  return CorrectFaultData ? 0 : 1;
}
