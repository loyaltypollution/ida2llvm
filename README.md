# IDA2LLVM - Dynamic Binary Lifting IDA code to LLVM IR

Because I was curious, "can Hexrays decompilation be hijacked for LLVM lifting"?


## Features

1. Lifts all IDA-decompilable binaries to LLVM bitcode, including executables and shared libraries for each platform.
2. **guarantees CFG preservation** during lifting
3. enable **interactive lifting**, for reverse-engineers most familiar with state-of-the-art IDA

TODO: describe visually certain feature sets

## Dependencies
| Name | Version | 
| ---- | ------- |
| [Python](https://www.python.org/) | 3.10* |
| [llvmlite](https://pypi.org/project/llvmlite/) | 0.39.1* |
| [headless-ida](https://pypi.org/project/headless-ida/)** | 0.5.2 |
| [pytest](https://pypi.org/project/pytest/)** | 7.4.3 |
| [IDA Pro](https://www.hex-rays.com/products/ida) | 7.7+ |

*llvmlite 0.39.1 did not have wheels for Python 3.11+  
**only needed for unittests

## Using the lifter

### Run as IDA Plugin

TODO: expose front-end IDA plugin

### Run in Docker

This requires an IDA Pro Windows installation.

Our Dockerfile runs Windows IDA Pro in a Linux container, emulating it in Wine. 

#### Step 1: Clone the repository

```pwsh
git clone https://github.com/loyaltypollution/ida2llvm
```

#### Step 2: Add `ida.tar` to `.devcontainer/dep`

Insert a tar zip of the entire IDA Pro folder 
```pwsh
tar cvf ida.tar "$(dirname "$(which ida64)")"
```

#### Step 3: Build & Run Dockerfile

TODO: expose a front-end in the Dockerfile for convenience purpose.

## Linking Notes

Suppose the user lifted all functions in the idb. This potentially includes symbols from the C standard library, such as `_start`.

Naievely compiling from `clang` will likely result in link issues. Common issues include:
- duplicate symbols
- undefined symbols

In general, link issues are not our concern. Our lifter has already done its work and it's up to the user to fix linking issues *(good luck)*. 

Here are some tips to fix linking issues:
- instruct the linker to use the first symbol seen (`allow-multiple-definition`)
    ```bash
        clang lifted.ll -c
        clang lifted.o -v -Wl,--allow-multiple-definition -o lifted.out
    ```
- cannot link against c++ stdlib*
    ```bash
        clang++ lifted.ll
    ```
*this solution is obviously superficial, please raise an issue and let the author learn more about cpp linking*