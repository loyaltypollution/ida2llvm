## Bin2LLVM

Given a source string $C$ and 

## How to Run
Set up the docker file.
```
DISPLAY=:0 PYTHONHOME="C:\\Program Files\\Python310" PYTHONPATH="C:\\Program Files\\Python310" wine ~/.wine/ida/idat64.exe -A -S"./src/core.py" examples/cff.i64 -t
```


## IDA Pro Disassembler
Ilfak Guilfanov gave a presentation at RECON where he explains the architecture of Hex-Rays decompiler. The main point of interest for us is its intermediate representation, called Microcode. At the start of the decompilation, the Microcode is simple and looks like RISC code. 

Then, multiple optimization passes are executed, which will make the look of the microcode change. Microcode instructions are condensed and made more complex.

Because microcode instructions are RISC-like, an additional layer of analysis is required to reconstruct high-level C structures such as `for`, `while`, `if`, `switch`. Hexray's has an additional intermediate representation called ctree which further aids final decompilation view.

### Decompilation view
Decompilation view is **compilable**, meaning that we can technically compile LLVM IR from the C-based decompilation view.

While this is convenient, our tool is better than such an approach as:
- Hexray's decompilation was never intended for accurate binary lifting but a trivial overview for reverse engineers to view their project.
- Each decompilation layer adds additional analysis and assumptions onto the IR, continually morphing the IR into a different form.
  - we skip ctree and clang layer by lifting directly to LLVM IR.
- During Ctree analysis, CFG are often manipulated for ease of human-reading.
  - we wish to preserve CFG between binary and lifted IR.

Notice further that such a naive compilation from Hexray's Decompiler
- is often unreliable, often facing compilation errors depending on the C compiler used.
- introduces additional compiler flags to tweak.

## Todo
This project is still ongoing, our various todos and technical limitations are noted in this section.

### todo: nested variadic function call
Given the C code snippet below,

```C
void innervariadic(...) {}
void outervariadic(arg1, ...) {
	innervariadic()
}
```

Note that if outervariadic is called with 5 arguments, innervariadic is called with 0 arguments. 
- IDA defaults to displaying nested variadic functions in the above manner
- the "issue" here is that variadic function arguments cannot propagate properly from outer to inner function
  - innervariadic function does not know how many arguments in outervariadic function
  - we also do not know how many arguments to pass from outervariadic to innervariadic function
- while this could be expected behaviour, there are situations where we wish for propagation of variadic arguments
- the typical fix involves va_list forwarding, however the project author is unclear how to perform this in IDA. *happy to receive Github issue for discussion :)*

The current "fix" for this is similar to GoLang languages: simply expand the number of arguments for all variadic arguments by an arbitrarily large number.
- this way, arguments that are used are correctly passed
- arguments that are not used are passed, but do not affect program flow

We have future plans to automate the above process into the project's workflow. In the interim, users are advised to expand the number of arguments themselves, by changing the type definition of variadic functions as above.

For instance, `int printf(char *format, ...)` $\rightarrow$ `int printf(char *format, int * a, int *b, int *c, int *d, ...)`

### todo: indirect memory access
Given the C code snippet below, 

```C
char a[40] = "hello world";
char b[20] = "other things";

int main() {
  int c;
  scanf("%d", &c);
  printf("%s", a + c);
}
```

An address is accessed with an offset. 
- at compile time, we do not know which memory location is accessed.
- at run time, `printf` is dependant on the memory layout of program $P$.
- at binary lift time, 
  - we do not know which memory location is accessed.
  - we wish for lifted `printf` to return the same result as program $P$
- therefore, our lifting code needs to maintain memory layout of the entire program, during **runtime**.

### todo: function call from memory access
It also stands to reason that function calls are difficult to lift. 
```C
int main() {
  int a = 0x1434;
  (void (*)(void *))a();
}
```
This technique is particularly troublesome as
- we need to disassemble and decompile at the new function offset, **at runtime**
  - at runtime, the program space can be modified. 
- our lifiting code needs to maintain memory layout of the entire program, during **runtime**.


<!-- ### comparision against other binary lifters
we conclude this section by comparing our various limitations to other state-of-the-art binary lifters. our comparisions are tabulated below

|our project| mcsema|
|--|--|
|--|--| -->