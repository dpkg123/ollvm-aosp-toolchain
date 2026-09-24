#ifndef LLVM_ADT_NONE_H
#define LLVM_ADT_NONE_H

namespace llvm {
/// A simple null object to allow implicit construction of Optional<T>
/// and similar types without having to spell out the specialization's name.
// (constant value 1 in an attempt to workaround MSVC build issue... )
enum class NoneType { None = 1 };
const NoneType None = NoneType::None;
}

#endif
