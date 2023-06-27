
"""
Missing Link IDA Plugin JSON DB loader
"""
import os
import sys
import json
from dataclasses import dataclass
from enum import IntFlag, unique, auto

"""
Transforming the input JSON dictionary and arrays into a series of data classes so the data is uniform and
can be easily accessed with a dot operator.
With the exception of 'ModuleFlags', when the module info flags need to be accessed, the data classes won't normally
need to be imported.
"""

@unique
class ModuleFlags(IntFlag):
    """Module flags"""
    IS_32BIT = auto()        # Is a 32bit module
    IS_TARGET = auto()       # Is the target module (will only be one)
    MISSING_UNLOAD = auto()  # TTD trace missing module unload event
    OVERLAP = auto()         # Overlaps one or more other modules
    DUPLICATE = auto()       # Has a duplicate short file name

    @staticmethod
    def str2flags():
        """Return a name to flag dictionary"""
        return {m.name: m for m in ModuleFlags}

@dataclass
class Module:
    """Module container."""
    path: str   # File path
    name: str   # File short name
    start: int  # Start/base address
    end: int    # End of module space
    flags: ModuleFlags
    load:  [int, int]   # TTD load time stamp [high, low]
    unload: [int, int]  # TTD unload time stamp [high, low]
    exports: dict[int, str]  # List of optional module exports


@dataclass
class BranchTarget:
    """Indirect branch target container."""
    address: int
    module_index: int
    hit_count: int

@dataclass
class IndirectBranch:
    """Indirect branch entry container."""
    source: int
    targets: list[BranchTarget]


def load(source_path: str) -> dict:
    """
    :param source_path: Path to JSON DB file
    :return: Loaded data in dictionary"
      "modules" = List of `Module` type.
      "target_index" = Target (IDA DB source module) index into "modules".
      "branches" = 'IndirectBranch' list of indirect branch entries.
    """
    output = {}

    # Load in the JSON DB (as a dictionary)
    with open(source_path, 'rt') as fp:
        jdict = json.load(fp)

    # Parse modules
    modules: list[Module] = []
    for m in jdict['modules']:
        exports: dict[int, str] = {}
        if m['exports']:
            for e in m['exports']:
                exports[e[0]] = e[1]
        modules.append(Module(m['path'], os.path.basename(m['path']), m['start'], m['end'], (m['flags'] & 0x1F), [m['load'][0], m['load'][1]], [m['unload'][0], m['unload'][1]], exports))

    output['modules'] = modules
    output['target_index'] = jdict['target_index']

    # Parse branches
    # Note: Probably a very rare edge case, but potentially a module could be unloaded then another loaded in the same
    #  address space and happens to have some of the same target address. Have to account for this still. Why the source
    #  has an array to cover scenario. Not a mistake.
    branches: list[IndirectBranch] = []
    for be in jdict['branches']:
        source: int = be[0]
        targets: list[BranchTarget] = []
        for te in be[1]:
            target: int = te[0]
            for ts in te[1]:
                module_index = ts[0]
                if module_index == 0xFFFFFFFF:  # -1 32bit
                    module_index = -1
                targets.append(BranchTarget(target, module_index, ts[1]))
        branches.append(IndirectBranch(source, targets))

    output['branches'] = branches
    return output


# Test: Load in ML DB and dump it
if __name__ == '__main__':
	#import ml_db_loader

    assert len(sys.argv) == 2, 'Missing DB path argument'
    data = load(os.path.normpath(sys.argv[1]))

    def serialize_prefix(indent: str, count: int) -> str:
        return f'{indent}[{{:0{len(f"{count}")}}}] '

    # Dump modules
    print('\nModules:')
    prefix = serialize_prefix('', len(data['modules']))
    for i, m in enumerate(data['modules']):
        export_count = 0
        if m.exports:
            export_count = len(m.exports)
        print(f'{prefix.format(i)}{m.start:014X}-{m.end:014X}, L: {m.load[0]:016X}:{m.load[1]:X}, U: {m.unload[0]:016X}:{m.unload[1]:X}, F: {m.flags:02}, EC: {export_count}, M: "{m.path}"')
        # Make 'True' to dump exports too
        if False:
            if export_count:
                for address, name in m.exports.items():
                    print(f'  {address:014X} "{name}"')
                print()

    my_index = data["target_index"]
    my_module = data["modules"][my_index]
    print(f'\nTarget module index: \"{my_module.name}\" ({my_index}), {32 if (my_module.flags & ModuleFlags.IS_32BIT) else 64}bit\n')

    # Dump branch info
    print('Indirect branches:')
    # Make 'True' for a source address list to compare with IDA output for verification test
    if False:
        for be in data['branches']:
            print(f'{be.source:08X}')
    else:
        for be in data['branches']:
            print(f'{be.source:014X}:')
            for te in be.targets:
                module_index = te.module_index
                #print(f' {te.address:014X} {module_index} {te.hit_count:,}')
                if module_index == -1:
                    # Not in known module space
                    print(f' {te.address:014X} * {te.hit_count:,}')
                else:
					# Get target module name and export label if it exists
                    module = data["modules"][module_index]
                    export_name = module.exports.get(te.address)
                    if export_name:
                        print(f' \"{module.name}\" \"{export_name}\" {te.hit_count:,}')
                    else:
                        print(f' \"{module.name}\" {te.address:014X} {te.hit_count:,}')
            print()
