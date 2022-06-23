#include "ArgumentLoader.h"
#include "Logger.h"
#include "PipeScanner.h"
#include "ProcessPipe.h"
#include "SquashFS.h"
#include "Common/Config.h"
#include "Common/FEXServerClient.h"

#include <chrono>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <iterator>
#include <mutex>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace Logging {
  const char *GetCharLevel(uint32_t Level) {
    switch (Level) {
    case LogMan::NONE:
      return "NONE";
      break;
    case LogMan::ASSERT:
      return "ASSERT";
      break;
    case LogMan::ERROR:
      return "ERROR";
      break;
    case LogMan::DEBUG:
      return "DEBUG";
      break;
    case LogMan::INFO:
      return "Info";
      break;
    case LogMan::STDOUT:
      return "STDOUT";
      break;
    case LogMan::STDERR:
      return "STDERR";
      break;
    default:
      return "???";
      break;
    }
  }
  void MsgHandler(LogMan::DebugLevels Level, char const *Message) {
    const auto Output = fmt::format("[{}] {}\n", GetCharLevel(Level), Message);
    write(STDOUT_FILENO, Output.c_str(), Output.size());
  }

  void AssertHandler(char const *Message) {
    const auto Output = fmt::format("[ASSERT] {}\n", Message);
    write(STDOUT_FILENO, Output.c_str(), Output.size());
  }

  void ClientMsgHandler(int FD, uint64_t Timestamp, uint32_t PID, uint32_t TID, uint32_t Level, const char* Msg) {
    auto CharLevel = GetCharLevel(Level);
    const auto Output = fmt::format("[{}][{}][{}.{}] {}\n", CharLevel, Timestamp, PID, TID, Msg);
    write(STDERR_FILENO, Output.c_str(), Output.size());
  }
}

namespace {
  void ActionHandler(int sig, siginfo_t *info, void *context) {
    // FEX_TODO("Fix this");
    if (sig == SIGINT) {
      // Someone trying to kill us. Shutdown.
      ProcessPipe::Shutdown();
      return;
    }
    _exit(1);
  }

  void ActionIgnore(int sig, siginfo_t *info, void *context) {
  }

  void SetupSignals() {
    // Setup our signal handlers now so we can capture some events
    struct sigaction act{};
    act.sa_sigaction = ActionHandler;
    act.sa_flags = SA_SIGINFO;

    // SIGTERM if something is trying to terminate us
    sigaction(SIGTERM, &act, nullptr);
    // SIGINT if something is trying to terminate us
    sigaction(SIGINT, &act, nullptr);

    // SIGUSR1 just to interrupt syscalls
    act.sa_sigaction = ActionIgnore;
    sigaction(SIGUSR1, &act, nullptr);

    // Ignore SIGPIPE, we will be checking for pipe closure which could send this signal
    signal(SIGPIPE, SIG_IGN);
    // SIGCHLD if squashfuse exits early.
    // Ignore it for now
    signal(SIGCHLD, SIG_IGN);
  }

  /**
   * @brief Deparents itself by forking and terminating the parent process.
   */
  void DeparentSelf() {
    pid_t pid = fork();

    if (pid != 0) {
      // Parent is leaving to force this process to deparent itself
      // This lets this process become the child of whatever the reaper parent is
      _exit(0);
    }
  }
}

int main(int argc, char **argv, char **const envp) {
  auto Options = FEXServer::Config::Load(argc, argv);

  SetupSignals();

  if (Options.Foreground) {
    LogMan::Throw::InstallHandler(Logging::AssertHandler);
    LogMan::Msg::InstallHandler(Logging::MsgHandler);
  }

  // Scan for any incoming pipes
  // We will close these later
  PipeScanner::ScanForPipes();

  if (!Options.Foreground) {
    DeparentSelf();
  }

  FEX::Config::LoadConfig(
    true,
    false,
    argc, argv, envp
  );

  // Reload the meta layer
  FEXCore::Config::ReloadMetaLayer();

  if (Options.Kill) {
    int ServerPipe = FEXServerClient::ConnectToServer();

    if (ServerPipe != -1) {
      FEXServerClient::RequestServerKill(ServerPipe);
      LogMan::Msg::DFmt("[FEXServer] Sent kill packet");
      PipeScanner::ClosePipes();
    }
    return 0;
  }

  if (!ProcessPipe::InitializeServerPipe()) {
    // Someone else already owns the FEXServer pipe
    PipeScanner::ClosePipes();
    return -1;
  }

  if (!ProcessPipe::InitializeServerSocket()) {
    // Couldn't create server socket for some reason
    PipeScanner::ClosePipes();
    return -1;
  }

  // Switch this process over to a new session id
  // Probably not required but allows this to become the process group leader of its session
  ::setsid();

  // Set process as a subreaper so subprocesses can't escape
  ::prctl(PR_SET_CHILD_SUBREAPER, 1);

  if (Options.Foreground) {
    // Only start a log thread if we are in the foreground.
    // Prevents FEXInterpreter from trying to log to nothing.
    Logger::StartLogThread();
  }

  if (!SquashFS::InitializeSquashFS()) {
    LogMan::Msg::DFmt("[FEXServer] Couldn't mount squashfs");
    return -1;
  }

  // Close the pipes we found at the start
  // This will let FEXInterpreter know we are ready
  PipeScanner::ClosePipes();

  ProcessPipe::SetConfiguration(Options.Foreground, Options.PersistentTimeout ?: 10);

  // Actually spin up the request thread.
  // Any applications that were waiting for the socket to accept will then go through here.
  ProcessPipe::WaitForRequests();

  SquashFS::UnmountRootFS();

  Logger::Shutdown();

  return 0;
}
