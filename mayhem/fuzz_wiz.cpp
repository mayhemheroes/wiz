// In-process libFuzzer harness for the `wiz` target: drives the SAME code path as the wiz CLI
// (option parsing -> Parser -> Compiler -> output format) via wiz::run(), the shared entry point
// used by both main() and the emscripten binding. Input is treated as a wiz source file compiled
// for the 6502 system; source and output live in a MemoryResourceManager, so each iteration is
// fully in-process and hermetic.
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include <wiz/utility/report.h>
#include <wiz/utility/logger.h>
#include <wiz/utility/array_view.h>
#include <wiz/utility/string_pool.h>
#include <wiz/utility/resource_manager.h>

namespace wiz {
    int run(Report* report, ResourceManager* resourceManager, ArrayView<const char*> arguments);
}

// wiz is an allocate-and-exit batch compiler (pools/arenas are freed only at process exit),
// so in-process iteration trips LSan on every compiled input.
extern "C" const char* __asan_default_options() {
    return "detect_leaks=0";
}

// The 6502 memory map imported by the seed corpus (`import "_6502_memmap.wiz";`), loaded once
// from the source tree so seeds compile end-to-end. Missing file just means imports fail cleanly.
static const std::string& memmap() {
    static const std::string contents = [] {
        const char* src = std::getenv("SRC");
        std::ifstream f(std::string(src ? src : "/mayhem") + "/tests/block/_6502_memmap.wiz");
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }();
    return contents;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    wiz::Report report(std::make_unique<wiz::MemoryLogger>());
    wiz::MemoryResourceManager resourceManager;
    // ImportManager canonicalizes module paths to normalized absolute paths before lookup,
    // so buffers must be registered under absolute names.
    resourceManager.registerReadBuffer("/input.wiz"_sv, std::string(reinterpret_cast<const char*>(data), size));
    resourceManager.registerReadBuffer("/_6502_memmap.wiz"_sv, memmap());

    const char* arguments[] = {"--system", "6502", "-o", "/out.bin", "/input.wiz"};
    wiz::run(&report, &resourceManager, wiz::ArrayView<const char*>(arguments, 5));
    return 0;
}
