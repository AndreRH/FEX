/*
$info$
tags: LinuxSyscalls|common
$end_info$
*/

#pragma once
#include <FEXCore/Config/Config.h>

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stddef.h>
#include <string>
#include <sys/stat.h>
#include <vector>

#include <unordered_map>
#include <unordered_set>

#include "Tests/LinuxSyscalls/EmulatedFiles/EmulatedFiles.h"

namespace FEXCore::Context {
struct Context;
}

namespace FEX::HLE {

struct open_how;

class FileManager final {
public:
  FileManager() = delete;
  FileManager(FileManager &&) = delete;

  FileManager(FEXCore::Context::Context *ctx);
  ~FileManager();
  uint64_t Open(const char *pathname, int flags, uint32_t mode);
  uint64_t Close(int fd);
  uint64_t CloseRange(unsigned int first, unsigned int last, unsigned int flags);
  uint64_t Stat(const char *pathname, void *buf);
  uint64_t Lstat(const char *path, void *buf);
  uint64_t Access(const char *pathname, int mode);
  uint64_t FAccessat(int dirfd, const char *pathname, int mode);
  uint64_t FAccessat2(int dirfd, const char *pathname, int mode, int flags);
  uint64_t Readlink(const char *pathname, char *buf, size_t bufsiz);
  uint64_t Chmod(const char *pathname, mode_t mode);
  uint64_t Readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
  uint64_t Openat(int dirfs, const char *pathname, int flags, uint32_t mode);
  uint64_t Openat2(int dirfs, const char *pathname, FEX::HLE::open_how *how, size_t usize);
  uint64_t Statx(int dirfd, const char *pathname, int flags, uint32_t mask, struct statx *statxbuf);
  uint64_t Mknod(const char *pathname, mode_t mode, dev_t dev);
  uint64_t NewFSStatAt(int dirfd, const char *pathname, struct stat *buf, int flag);
  uint64_t NewFSStatAt64(int dirfd, const char *pathname, struct stat64 *buf, int flag);

  // vfs
  uint64_t Statfs(const char *path, void *buf);

  std::string *FindFDName(int fd);

  std::optional<std::string> GetSelf(const char *Pathname);

  void UpdatePID(uint32_t PID) { CurrentPID = PID; }

  std::string GetEmulatedPath(const char *pathname, bool FollowSymlink);

  std::mutex *GetFDLock() { return &FDLock; }

private:
  FEX::EmulatedFile::EmulatedFDManager EmuFD;

  std::mutex FDLock;
  std::unordered_map<int32_t, std::string> FDToNameMap;
  std::map<std::string, std::string, std::less<>> ThunkOverlays;

  FEX_CONFIG_OPT(Filename, APP_FILENAME);
  FEX_CONFIG_OPT(LDPath, ROOTFS);
  FEX_CONFIG_OPT(ThunkHostLibs, THUNKHOSTLIBS);
  FEX_CONFIG_OPT(ThunkGuestLibs, THUNKGUESTLIBS);
  FEX_CONFIG_OPT(ThunkConfig, THUNKCONFIG);
  uint32_t CurrentPID{};

  void LoadThunkDatabase(bool Global);
  struct ThunkDBObject {
    std::string LibraryName;
    std::unordered_set<std::string> Depends;
    std::vector<std::string> Overlays;
    bool Enabled{};
  };
  std::unordered_map<std::string, ThunkDBObject> ThunkDB{};
};
}
