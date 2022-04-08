# Vuln Observer

## What?

A tool to test the presence of a known vuln in a binary.

Oriented towards macOS and iOS (parsing of IPSW content).

The vuln properties and indicators should be described in a JSON file.

Once the tool done, users should be able to focus only on the vulns description in a relatively
high-level view.

## Tech

* r2 : everything related to handling executable (parsing, analyzing, emulation, etc.)
* python

## Requirements

* Parsing an archive (zip) content
* Basic file diffing
* Get basic block graph
    * Implement the Machoc algo?

## Vuln description

cf. vuln.json

### Info extraction

First we need to extract some informations from our vulnerable targe: function, range we want to
emulate, strings to identify the function, etc.

For most it's straightforward once the vuln is identified. Other are more complex, like the range
for which we want to emulate code. Obviously we can't use addresses. My approach for this is to
first generate the basic block graph of the function then use basic block ID to identify the range.

This should be automated by a script which takes 2 addresses as input and gives the graph path
between the 2 basic blocks containing those addresses.
Cf. EMULATION attribute

### Attributes

An attribute is defined by a TYPE. Each TYPE defines its own set of objects.

**FILE**

{"str": "", "hash": ""}
* *name*: required
* *hash*: optional

**subtypes(?)**

* `filenames`   : A list of files that should be present in the archive.
    * {"absolute": true/false, "name": "filename"}
* `hash`        : A list file hashes that should be present.
* `absolutes`   : A list of exact paths that should be present in the archive.
* `dyld`        : A list of .dylib that should be present in the sharedcache.

**FUNCTION**

Characteristics allowing the identification of a function.

* `identifier` : A list of elements to identify the function from the binary.
    **subtypes(?)**
    * `symbol`     : Function name.
    * `strings`    : A list of strings that should be present in the function.
    * `bb_graph`   : An object describing the basic block graph of the function.
        * {"hash": "", "path": "local_file_containing_graph"}
        * Compute graph edit distance?

**EMULATION**

Portion of the code to analyze dynamically. Emulation is done with radare2's ESIL feature. It
abstracts the code with an Intermediary Language then evaluates this IL.

Run first on the vulnerable version to get a reference and to decide which attributes to look for.

**subtypes(?)**
divide thme between mandatory/optional?

* `start`         : Basic block ID.
    * Limit the scope of the analysis to start-end.
    * The actual emulation can cover all the blocks of the range or a subset of instructions
    identified by "keypoints".
    * {type: bb_id, id: 0}
    //* {bb_id: 0, keypoint: {name: none/first/last/branch/memread/memwrite/etc., position: 0}}
* `end`           : Basic block ID.
    * {type: bb_id, id: 5}
* `keypoint_start`
    * {type: branch, position: 3} // start at the 3rd call/jmp/branch
    * types: branch, memread, memwrite, offset
* `keypoint_end`
    * {type: branch, position: 3} // start at the 3rd call/jmp/branch
    * types: branch, memread, memwrite, offset
* `commands`      : ESIL commands or abstractions of ESIL command
    * values referenced in "object" (function or basic block)
    * number of PC changes (branch, jmp, call)
    * memreads and memwrites at specific offsets
    * stack content
    * nb values pushed on the stack between start and now
* `context`       : Initial context to setup emulation with.
    * memory
    * register
    * stack
    * {}
* `register`      : Expected value in registers
    * {}
* `stack`
    * {type: value/pointer, value: 0x00/"bytes"}

## Analysis

Done with `r2` because faster and more appropriate for this kind of use case than `IDA`
To be confirmed whne handling a single dyldcache module.

### MACHOC

`afb` to get a list of basic blocks

## Handle dyldcache

* r2   : https://github.com/radareorg/radare2/pull/10094
* idat : https://hex-rays.com/products/ida/news/7_2/the_mac_rundown/

## TESTS

Test target: `ls`

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
    * get memory read access, should be only one, set it to "something"
2. the one containing the vuln
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


### IOMobileFrameBuffer

https://saaramar.github.io/IOMobileFrameBuffer_LPE_POC/

## TODO

* Check number of function calls between two points
* A set of high-level commands, translated in the code to ESIL commands
* Get an ESIL string to experiment with
