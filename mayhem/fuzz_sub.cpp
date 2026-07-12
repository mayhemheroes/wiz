#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "string_view.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    std::size_t index = provider.ConsumeIntegral<std::size_t>();
    wiz::StringView sv(str);

    sv.sub(index);

    return 0;
}
