#pragma once
#include <cstdlib>
#include <stdint.h>
#include <type_traits>

#include "PackedArguments.h"

template<typename signature>
struct fexthunks_invoke_callback { };

#ifndef _M_ARM_64
#define MAKE_THUNK(lib, name, hash) \
  extern "C" int fexthunks_##lib##_##name(void *args); \
  asm(".text\nfexthunks_" #lib "_" #name ":\n.byte 0xF, 0x3F\n.byte " hash );

#define MAKE_CALLBACK_THUNK(name, signature, hash) \
  extern "C" int fexthunks_##name(void *args); \
  asm(".text\nfexthunks_" #name ":\n.byte 0xF, 0x3F\n.byte " hash ); \
  template<> struct fexthunks_invoke_callback<signature> { static inline constexpr int (*value)(void*) = fexthunks_##name; }

#else
// We're compiling for IDE integration, so provide a dummy-implementation that just calls an undefined function.
// The name of that function serves as an error message if this library somehow gets loaded at runtime.
extern "C" void BROKEN_INSTALL___TRIED_LOADING_AARCH64_BUILD_OF_GUEST_THUNK();
#define MAKE_THUNK(lib, name, hash) \
  extern "C" int fexthunks_##lib##_##name(void *args) { \
    BROKEN_INSTALL___TRIED_LOADING_AARCH64_BUILD_OF_GUEST_THUNK(); \
    return 0; \
  }
#define MAKE_CALLBACK_THUNK(name, signature, hash) \
  extern "C" int fexthunks_##name(void *args); \
  template<> struct fexthunks_invoke_callback<signature> { static inline constexpr int (*value)(void*) = fexthunks_##name; }
#endif

// Generated fexfn_pack_ symbols should be hidden by default, but clang does
// not support aliasing to static functions. Make them regular non-static
// functions on that compiler instead, hence.
#if defined(__clang__)
#define FEX_PACKFN_LINKAGE
#else
#define FEX_PACKFN_LINKAGE static
#endif

struct LoadlibArgs {
    const char *Name;
    uintptr_t CallbackThunks;
};

MAKE_THUNK(fex, loadlib, "0x27, 0x7e, 0xb7, 0x69, 0x5b, 0xe9, 0xab, 0x12, 0x6e, 0xf7, 0x85, 0x9d, 0x4b, 0xc9, 0xa2, 0x44, 0x46, 0xcf, 0xbd, 0xb5, 0x87, 0x43, 0xef, 0x28, 0xa2, 0x65, 0xba, 0xfc, 0x89, 0x0f, 0x77, 0x80")
MAKE_THUNK(fex, is_lib_loaded, "0xee, 0x57, 0xba, 0x0c, 0x5f, 0x6e, 0xef, 0x2a, 0x8c, 0xb5, 0x19, 0x81, 0xc9, 0x23, 0xe6, 0x51, 0xae, 0x65, 0x02, 0x8f, 0x2b, 0x5d, 0x59, 0x90, 0x6a, 0x7e, 0xe2, 0xe7, 0x1c, 0x33, 0x8a, 0xff")
MAKE_THUNK(fex, is_host_heap_allocation, "0xf5, 0x77, 0x68, 0x43, 0xbb, 0x6b, 0x28, 0x18, 0x40, 0xb0, 0xdb, 0x8a, 0x66, 0xfb, 0x0e, 0x2d, 0x98, 0xc2, 0xad, 0xe2, 0x5a, 0x18, 0x5a, 0x37, 0x2e, 0x13, 0xc9, 0xe7, 0xb9, 0x8c, 0xa9, 0x3e")
MAKE_THUNK(fex, link_address_to_function, "0xe6, 0xa8, 0xec, 0x1c, 0x7b, 0x74, 0x35, 0x27, 0xe9, 0x4f, 0x5b, 0x6e, 0x2d, 0xc9, 0xa0, 0x27, 0xd6, 0x1f, 0x2b, 0x87, 0x8f, 0x2d, 0x35, 0x50, 0xea, 0x16, 0xb8, 0xc4, 0x5e, 0x42, 0xfd, 0x77")
MAKE_THUNK(fex, allocate_host_trampoline_for_guest_function, "0x9b, 0xb2, 0xf4, 0xb4, 0x83, 0x7d, 0x28, 0x93, 0x40, 0xcb, 0xf4, 0x7a, 0x0b, 0x47, 0x85, 0x87, 0xf9, 0xbc, 0xb5, 0x27, 0xca, 0xa6, 0x93, 0xa5, 0xc0, 0x73, 0x27, 0x24, 0xae, 0xc8, 0xb8, 0x5a")

#define LOAD_LIB_BASE(name, init_fn) \
  __attribute__((constructor)) static void loadlib() \
  { \
    LoadlibArgs args =  { #name }; \
    fexthunks_fex_loadlib(&args); \
    if ((init_fn)) ((void(*)())init_fn)(); \
  }

#define LOAD_LIB(name) LOAD_LIB_BASE(name, nullptr)
#define LOAD_LIB_INIT(name, init_fn) LOAD_LIB_BASE(name, init_fn)

inline void LinkAddressToFunction(uintptr_t addr, uintptr_t target) {
    struct args_t {
        uintptr_t original_callee;
        uintptr_t target_addr; // Function to call when branching to replaced_addr
    };
    args_t args = { addr, target };
    fexthunks_fex_link_address_to_function(&args);
}

inline bool IsLibLoaded(const char *libname) {
  struct {
    const char *Name;
    bool rv;
  } argsrv = { libname };

  fexthunks_fex_is_lib_loaded(&argsrv);

  return argsrv.rv;
}

// Helper template that packs the given arguments and invokes a thunk at the
// address stored in the `r11` guest register. The signature of the thunk must
// be specified at compile-time via the Thunk template parameter.
// Other than reading the thunk address from `r11`, this is equivalent to the
// fexfn_pack_* functions generated for global API functions.
template<auto Thunk, typename Result, typename... Args>
inline Result CallHostFunction(Args... args) {
  uintptr_t host_addr;
  #if defined(_M_X86_64) && defined(guest_arch_x86_64)
    asm volatile("mov %%r11, %0" : "=r" (host_addr));
  #elif defined(_M_X86_64) && defined(guest_arch_x86_32)
    asm volatile("mov %%ecx, %0" : "=r" (host_addr));
  #else
    std::abort();
  #endif

    PackedArguments<Result, Args..., uintptr_t> packed_args = {
        args...,
        host_addr
        // Return value not explicitly initialized since an initializer would fail to compile for the void case
    };

    Thunk(reinterpret_cast<void*>(&packed_args));

    if constexpr (!std::is_void_v<Result>) {
        return packed_args.rv;
    }
}

// Convenience wrapper that returns the function pointer to a CallHostFunction
// instantiation matching the function signature of `host_func`
template<typename Result, typename...Args>
static auto GetCallerForHostFunction(Result (*host_func)(Args...))
    -> Result(*)(Args...) {
  return &CallHostFunction<fexthunks_invoke_callback<Result(Args...)>::value, Result, Args...>;
}

// Ensures the given host function can safely be called from guest code.
template<typename Result, typename...Args>
inline void MakeHostFunctionGuestCallable(Result (*host_func)(Args...)) {
  auto caller = (uintptr_t)GetCallerForHostFunction(host_func);
  LinkAddressToFunction((uintptr_t)host_func, (uintptr_t)caller);
}

template<typename Target>
inline Target *AllocateHostTrampolineForGuestFunction(void (*GuestUnpacker)(uintptr_t, void*), Target *GuestTarget) {
  if (!GuestTarget) {
    return nullptr;
  }

  struct {
    uintptr_t GuestUnpacker;
    uintptr_t GuestTarget;
    uintptr_t rv;
  } argsrv = { (uintptr_t)GuestUnpacker, (uintptr_t)GuestTarget };

  fexthunks_fex_allocate_host_trampoline_for_guest_function((void*)&argsrv);

  return (Target *)argsrv.rv;
}

template<typename F>
struct CallbackUnpack;

template<typename Result, typename... Args>
struct CallbackUnpack<Result(Args...)> {
    static void Unpack(uintptr_t cb, void* argsv) {
        using fn_t = Result(Args...);
        auto callback = reinterpret_cast<fn_t*>(cb);
        auto args = reinterpret_cast<PackedArguments<Result, Args...>*>(argsv);
        Invoke(callback, *args);
    }
};

template<typename Result, typename... Args>
struct CallbackUnpack<Result(*)(Args...)> : CallbackUnpack<Result(Args...)> {
};

template<typename Target>
inline Target *AllocateHostTrampolineForGuestFunction(Target *GuestTarget) {
    return AllocateHostTrampolineForGuestFunction(CallbackUnpack<Target*>::Unpack,
                                                  GuestTarget);
}

inline bool IsHostHeapAllocation(void* ptr) {
    struct {
        void* ptr;
        bool rv;
    } args = { ptr, {} };

    fexthunks_fex_is_host_heap_allocation(&args);
    return args.rv;
}
