# Vuln Oberserver

## Description

Script to search for a known vulnerability in a binary. The vulnerability is described as a set of
attributes defined in a `.json` file. The script takes one of those as input to determine if it is
still present in the targeted binary.

Binary analysis and/or emulation is done with `radare2` (the emulation uses the ESIL feature of
`r2`), which is particularly well suited for this kind of use case.

For know it handles simple binary as well as `dyldcache` file.

## How to use

### Extract information

At first the tool can be used to extract the necessary information to identify a vulnerability. The
following command extract basic block ID and generate the basic block graph (GML format) for the
functions containing the addresses passed on the command line:

```bash
python kvd.py -e 0x1000F5380 0x1000F53A8 -t tests/wifid_14.1
```

### Search for a vuln

`tests/wifid.json` is not automatically generated, it has to be done manually. This one can be used
as a template. Attributes available for the crafting of a descrition are listed in `DOC.md`.

```bash
python kvd.py -s tests/wifid.json -t tests/wifid_14.1 -vv
```

### Run unit tests

```
make test
```
