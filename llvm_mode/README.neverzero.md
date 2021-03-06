# NeverZero counters for LLVM instrumentation

## Usage

In larger, complex or reiterative programs the map that collects the edge pairs
can easily fill up and wrap.
This is not that much of an issue - unless by chance it wraps just to a 0
when the program execution ends.
In this case afl-fuzz is not able to see that the pair has been accessed and
will ignore it.

NeverZero prevents this behaviour. If a counter wraps, it jumps over the 0
directly to a 1. This improves path discovery (by a very little amount)
at a very little cost (one instruction per edge).

This is implemented in afl-gcc, however for llvm_mode this is optional if
the llvm version is below 9 - as there is a perfomance bug that is only fixed
in version 9 and onwards.

If you want to enable this for llvm < 9 then set

```
export AFL_LLVM_NOT_ZERO=1
```
