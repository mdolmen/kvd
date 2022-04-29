# Vuln Observer

## Info extraction

First we need to extract some informations from our vulnerable target: function, range we want to
emulate, strings to identify the function, etc.

It's mostly straightforward once the vuln is identified. Some attributes more complex, like the range
for which we want to emulate code. Obviously we can't use addresses. My approach for this is to
first generate the basic block graph of the function then use basic block ID to identify the range.

## Vuln description

For a complete example see `tests/wifid.json`.

### Metadata

Information describing the vuln and its target. A good place to store research related resources
(e.g. path to IDB).

### Revisions

The idea is that the **same** vuln may have slight variations (an additional baisc block, a few missing
instructions for optimization which impacts the emulation logic done so far, etc.) depending on the
target's version, maybe because of compiler options (release vs debug build) or the OS. So instead
of having a single file for each one, we can put them all in a single description.

Maybe it will be clearer without, we'll see how this turns out in practice.

### Attributes

The analysis is done in this order, from simpler to more complex. An attribute can be seen as a
constraint and each step requires that the previous constraint be satisfied.

An attribute is defined by a `TYPE`. Each `TYPE` defines its own set of objects.

All the fields are required but their content is optional (can be empty).

**FUNCTION**

Characteristics to use to identify a function.

* `type`        : FUNCTION
* `fct_id`      : Arbitrary id. Used by `EMULATION`.
* `identifier`  : A list of elements to identify the function from the binary. All have to match.
    * `type`  : "symbol", "string", "graph" (not implemented yet)
    * `name`  : The content of the symbol/string (TODO: rename content)

Can be use just to ensure its presence or to apply EMULATION on it.

**EMULATION**

Portion of the code to analyze dynamically. Emulation is done with radare2's ESIL feature. It
abstracts the code with an Intermediary Language then evaluates this IL.

* `type`                : EMULATION
* `fct_id`              : The FUNCTION ID to apply the emulation logic on.
* `bb_graph_filepaths`  : The path to the .gml file containing the graph of the function. There can
                          be multiple files listed here.
* `bb_graph_path`       : The graph simple path between two basic block ID. This identify the
                          start/end range for the emulation.
* `context`             : To setup the memory state or register values (not implemented yet).
* `commands`            : A list of action (`cmd`) to perform on the range given by `bb_graph_path`.

**EMULATION - cmd**

* `cmd` : The name of the command to execute.
    * `get_memreads` : Get the list of addresses at which memory is read.
    * `exec_until`   : Emulate (i.e. evaluate the ESIL expression) until `keypoint`.
* `keypoint` : An object defining where to stop the emulation.
    * Not used by `get_memreads`.
    * `type`     : The keypoint name (only "branch" for now).
    * `expected` : The expected number of occurence of that keypoint in the range analyzed.
    * `position` : The index at which to stop/act.
* `results` : An object describing the expected state resulting from the emulation.
    * Can be empty.
    * `type`    : "stack" or "callback" (TODO: "reg" and "mem")

**EMULATION - cmd: results**

* `type` == "stack" (handling of regs is the same, yet to be implemented though)
    * Check the state of the stack.
    * `offset`  : An offset from the stack pointer.
    * `deref`   : Boolean to indicate wether or not we are interested in the stack value or what it
                  points to.
    * `value`   : The expected value.
    * `operand` : A string representing the operand to apply (e.g. "==").
* `callback` : An object to describe an action to apply on one of the elements returned by the
               execution of `cmd`.
    * `elem_id` : The index of the element on which to apply `action`.
    * `action`  : "write" (TODO: implement more)
    * `value`   : An argument for `action`.

## Tests

### Experiments with ls

Function: `sub_D910`, `sub_CD30` (more complex)
Easy for graph generation test: sub_7710 (statx)

### (iOS) wifid

https://blog.zecops.com/research/meet-wifidemon-ios-wifi-rce-0-day-vulnerability-and-a-zero-click-vulnerability-that-was-silently-patched/

Type: Format string
Function: `sub_1000F4EF8` (14.1); `sub_1000FCF04` (14.7.1)
String: "Scanning(%s) for MRU Networks", 1 xref

Same call graph in both versions perfect for testing!

**14.1**

Basic block containing the vuln
* start : 0x1000F53A8
* end   : 0x1000F5418

As a check we can run until the call to:
```cpp
objc_msgSend(
              &OBJC_CLASS___NSString,
              "stringWithFormat:",
              CFSTR("Scanning(%s) for MRU Networks: %@"),
              "Active",
              v35);
```

And inspect the stack (ESIL context). It's a format-string vuln on this call. Since it's
objc_msgSend(), the arguments passed to the selector "strignWithFormat" are on the stack. Before
that call we want to see 2 pointers on the stack, one being the "Active" string and the other
variable data we control (`X27` == `v35`).

Here a patch could be to remove `X27` as an arg (the actual patch that was made) or to change the
building logic of the string which would mean a change in the control flow graph. In that case we
would be signaled by the script that there is something we need to check out.

2 blocks to analyze:
1. ldr x27, string
    * start @ = 0x1000F5380; bb id = 49
    * get memory read access, should be only one, set it to "something"
2. the one containing the vuln
    * start @ = 0x1000F53A8; bb id = 51
    * get stack value
    * emulate until call to obj_msgSend
    * check stack value == stack_value_before - 16 (2 args pushed)
    * check stack

**14.7.1**

Basic block containing the vuln
* start : 0x1000FD3CC
* end   : 0x1000FD434

(14.1)   : 16,sp,-=,x8,sp,=[8],x27,sp,8,+,=[8]
(14.7.1) : 16,sp,-=,x20,0x10,sp,-,=[8]


### (iOS) IOMobileFrameBuffer

TODO: handle kernelcache

https://saaramar.github.io/IOMobileFrameBuffer_LPE_POC/

## Notes

### Handle dyldcache

* r2   : https://github.com/radareorg/radare2/pull/10094
    * `R_DYLDCACHE_FILTER=whatever.dylib r2 -e bin.usextr=false <dyldcache>`
* idat : https://hex-rays.com/products/ida/news/7_2/the_mac_rundown/
### MACHOC

TODO: use a similar algorithm to look for a function

https://github.com/ANSSI-FR/polichombr/blob/dev/docs/MACHOC_HASH.md
