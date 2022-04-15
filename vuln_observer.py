#!/usr/bin/env python3

import r2pipe
import re
import argparse
import inspect
import subprocess
import json
import pickle

from colorama import Fore, Style, init as colorama_init
from tempfile import NamedTemporaryFile
from igraph import Graph
from base64 import b64encode, b64decode

## Get a single basic block as an ESIL string
#bb_index = 13 # TODO: get basic block containing address (pdb does that!)
#basic_blocks = r.cmdj("afbj")
#bb = basic_blocks[bb_index]
#
#print(bb['addr'])
#print(bb['size'])
#print(f"addr = {bb['addr']}")
#r.cmd(f"s {bb['addr']}")
#disas = r.cmdj(f"pDj {bb['size']}")

#esil = "".join(inst["esil"] for inst in disas)
#esil = "0x58,rbp,+,[8],rdi,=0x1488b,rip,+,[8],r8,=rsp,rsi,=512,rcx,=0x14885,rip,+,[4],rdx,=52528,rip,8,rsp,-=,rsp,=[],rip,=rax,rdi,=18592,rip,8,rsp,-=,rsp,=[],rip,=1,rax,+=,63,$o,of,:=,63,$s,sf,:=,$z,zf,:=,63,$c,cf,:=,$p,pf,:=0xd972,rip,="

class Utils():
    @staticmethod
    def log(type, msg):
        if type == 'error':
            print(f'{Fore.RED}[!] {inspect.stack()[1].function}{Style.RESET_ALL}: {msg}')
            exit(1)
        elif type == 'fail':
            print(f'{Fore.RED}[-]{Style.RESET_ALL} {msg}')
        elif type == 'success':
            print(f'{Fore.GREEN}[+]{Style.RESET_ALL} {msg}')
        elif type == 'info':
            print(f'{Fore.YELLOW}[*]{Style.RESET_ALL} {msg}')
        elif type == 'debug':
            print(f'{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {msg}')
        else:
            print(f'{msg}')

    @staticmethod
    def present_in_both(a, b):
        """
        Returns a list of elements present in both list.
        """
        result = []

        if len(a) or len(b) == 0:
            return result

        result = [result.append(elem) for elem in b if elem in a]

        return result


class VulnObserver():
    def __init__(self, target):
        colorama_init()

        self.desc = None
        self.fct_candidates = []
        self.options = self.init_options(target)
        self.r = r2pipe.open(target, self.options)

        # TODO: fine tune the analysis depending of the needs for faster load
        #Utils.log('info', 'Analyzing the binary...')

        # TEST: to speed up testing, r2 project feature works \o/
        if 'wifid' in target:
            Utils.log('info', 'Opening project...')
            self.r.cmd('Po wifid_14_1')
        else:
            Utils.log('info', 'Analyzing the binary...')
            self.r.cmd('aaa')

        # Init ESIL
        self.r.cmd('aei')
        sefl.r.cmd('aeim')
        self.r.cmd('e asm.esil=true')

        #self.curr_fct
        #self.curr_graph

    def init_options(self, target):
        """
        Use rabin2 to get information about the binary to determine what we have to deal with.
        """
        options = []

        bin_info = subprocess.check_output(['rabin2', '-Ij', target])
        bin_info = json.loads(bin_info)
        bin_info = bin_info['info']

        if bin_info['bintype'] == 'mach0':
            pass

        # TODO: check if dyldcache

        elif bin_info['bintype'] == 'elf':
            if bin_info['relro'] == 'full':
                options += ['-e', 'bin.cache=true']

        return options

    def get_calls(self, pc, esil):
        """
        Args:
            pc   : The register name for PC
            esil : The ESIL string in which to search for

        Returns: The indexes at which PC gets changed (branch, jmp, call).
        """
        return [m.start() for m in re.finditer(f"{pc},=", esil)]

    def get_fct_range(self, addr):
        """
        Return start and end address of the function containing addr.
        """
        info = self.r.cmdj(f'afij @ {addr}')

        if len(info) == 0:
            Utils.log('error', f'no function found containing {hex(addr)}')
        
        return (info[0]['offset'], info[0]['offset']+info[0]['size'])

    def get_bbs(self, addr):
        basic_blocks = self.r.cmdj(f'afbj @ {addr}')
        return basic_blocks

    def get_bb_ids(self, addresses):
        """
        Get basic block IDs containing each address.
        """
        Utils.log('info', f'Searching basic block IDs for {addresses}...')

        bb_ids = []

        for addr in addresses:
            start, end = self.get_fct_range(addr)
            bbs = self.get_bbs(addr)

            index = 0
            for bb in bbs:
                if addr >= bb['addr'] and addr <= bb['addr']+bb['size']:
                    bb_ids.append(index)
                index += 1

            # TODO: handle case not found (r2 analysis failed to interpret as code)

        return bb_ids

    def get_memreads(self):
        pass
    
    def get_graph(self, addr, show=False):
        """
        Return the GML graph of the function containing 'addr'.
        """
        # 'agfg' command doesn't have a JSON option for output and the JSON format of the graph is
        # not as concise as the GML one.
        tmp = NamedTemporaryFile()
        self.r.cmd(f'agfg @ {addr} > {tmp.name}')
        start, _ = self.get_fct_range(addr)

        # Create GML graph from file
        g = Graph()
        result = g.Read_GML(tmp.name)
        tmp.close()

        # Serialize the graph and format for a vuln decription
        graph = b64encode(pickle.dumps(result)).decode('utf-8')
        output = json.dumps({'label': f'fct_{hex(start)}', 'graph': graph})
        if show:
            Utils.log('info', f'Serialized graph for function containing {hex(addr)}:')
            Utils.log('', output)

        return result

    def get_graph_paths(self, g, start, end):
        return g.get_all_simple_paths(start, to=end)

    def get_graph_from_desc(self, label):
        """
        Get the data related to graph "label" from the desc, decode, deserialize and return a graph
        object from it.
        """
        data = {}

        for g in self.desc['graphs']:
            if g['label'] == label:
                data = g
                break

        if data == {}:
            Utils.log('error', f'Graph \"{label}\" was not found')

        graph = pickle.loads(b64decode(data['graph']))

        return graph

    def check_description(self, desc):
        """
        Check the format correctness of a vuln description file.
        """
        assert len(desc['metadata']) != 0, "Vuln description error: empty metadata"
        assert len(desc['revisions']) != 0, "Vuln description error: empty revisions, nothing to look for"
        # TODO: ...
        Utils.log('success', 'Description OK')

    def handle_attribute(self, att):
        """
        Handle an attribute from the vuln that should be present in the target we test.
        """
        if att['type'] == 'FILE':
            #self.handle_att_file()
            pass
        elif att['type'] == 'FUNCTION':
            self.handle_att_function(att['identifiers'])
        elif att['type'] == 'EMULATION':
            #self.handle_att_emulation(att)
            pass

    def handle_att_file(self):
        return True

    # TODO: start by handling this one
    def handle_att_function(self, identifiers):
        """
        Look for the function matching the constraints described in 'identifiers'.
        Return the start address of all the functions matching.
        """
        # Potential function matching the constraints
        candidates = []
        found = True

        for id in identifiers:
            if id['type'] == 'symbol':
                pass
            elif id['type'] == 'string':
                candidates = self.handle_obj_id_string(id, candidates)
            elif id['type'] == 'bb_graph':
                pass

            if len(candidates) == 0:
                found = False
                Utils.log('fail', f'FUNCTION: \"{id["type"]}\" \"{id["value"]}\": no function matching previous constraints')
                break

        if found:
            Utils.log('success', f'Found a matching function: {hex(candidates[0])}')
            # TODO: handle multiple function still matches

        return candidates

    def handle_att_emulation(self, att):
        # TODO: get graph path from bb_id_start to bb_id_end

        # TODO: apply 'context'

        for cmd in att['commands']:
            self.handle_obj_cmd(cmd, graph)

        return True
    
    def handle_obj_cmd(self, obj, graph):
        if obj['cmd'] == 'get_memreads':
            self.cmd_get_memreads()
        if obj['cmd'] == 'exec_until':
            self.cmd_exec_until()

    def handle_obj_id_string(self, obj, candidates):
        result = self.r.cmd(f'iz~{obj["value"]}')

        if result:
            addr = result.split(' ')[2]

            # Get xrefs to the string
            xrefs = self.r.cmdj(f'axtj {addr}')

            new_candidates = [ref['fcn_addr'] for ref in xrefs]
            if len(candidates) == 0:
                # No other result yet, it's the first constraint being tested.
                return new_candidates

            # If one of the new candidates is not already in the existing candidate list
            # it means it doesn't match previous criterias so we can remove it.
            candidates = Utils.present_in_both(candidates, new_candidates)

            Utils.log('debug', f'handle_id_string: {candidates}')

        return candidates

    def cmd_get_memreads(self):
        reg_mem_accesses = self.r.cmd(f'aeabj @ {addr}')
        return reg_mem_accesses['@R']

    def cmd_exec_until(self):
        pass
    
    def search_vuln(self, desc_file):
        self.desc = json.load(desc_file)
        self.check_description(self.desc)

        for rev in self.desc['revisions']:
            for att in rev['attributes']:
                self.handle_attribute(att)
            # TODO: print conclusion for revision, 'found' or 'maybe patched'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--get-bb-ids', nargs='*',
                        help='Get the basic block IDs corresponding to the given addresses')
    parser.add_argument('-g', '--get-graph', nargs='*',
                        help='Get the graph representation of a function (GML format)')
    parser.add_argument('-e', '--extract', nargs='*',
                        help='Get all info pertaining to the given addresses (BB IDs + graph)')
    parser.add_argument('-s', '--search', type=argparse.FileType('r'),
                        help='JSON file describing a vulnerability to look for')
    parser.add_argument('-c', '--check', type=argparse.FileType('r'),
                        help='Check the correctness of a description file')
    parser.add_argument('-t', '--target', required=True,
                        help='Target file in which to search for the given vuln')
    args = parser.parse_args()

    vo = VulnObserver(args.target)
    #vo.get_graph(0x77AE)
    #vo.desc = json.load(args.search)
    #vo.get_graph_from_desc("fct_0x1000f4ef8")
    #exit(1)

    # TEST: run it with: 0x77AE 0x7890

    if args.extract:
        # TODO: get_bb_ids
        # TODO: get_graph
        pass

    if args.get_bb_ids:
        addresses = [int(a, 16) for a in args.get_bb_ids]
        bb_ids = vo.get_bb_ids(addresses)

        # TODO: output in json ready to be copy/pasted in a description file
        for i in range(len(args.get_bb_ids)):
            print(f"Basic block ID of {hex(addresses[i])}: {bb_ids[i]}")
        exit(0)

    if args.get_graph:
        addresses = [int(a, 16) for a in args.get_graph]
        graphs = []

        for addr in addresses:
            graphs.append(vo.get_graph(addr), show=True)

    if args.check:
        self.desc = json.load(desc_file)
        vo.check_description()

    if args.search:
        vo.search_vuln(args.search)
