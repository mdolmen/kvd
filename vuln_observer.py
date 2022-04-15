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

"""
ESIL doc: https://book.rada.re/disassembling/esil.html
"""

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
            print(f'{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {inspect.stack()[1].function}: {msg}')
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
        self.r.cmd('aeim')
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
        """
        Returns the basic blocks of the function containing 'addr'.
        """
        return self.r.cmdj(f'afbj @ {addr}')

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
                if addr >= bb['addr'] and addr < bb['addr']+bb['size']:
                    bb_ids.append(index)
                index += 1

            # TODO: handle case not found (r2 analysis failed to interpret as code)

        return bb_ids

    def get_memreads(self, addr):
        """
        Returns the memory reads done at the basic block containing 'addr'.
        """
        reg_mem_accesses = self.r.cmdj(f'aeabj @ {addr}')
        Utils.log('debug', reg_mem_accesses)
        return reg_mem_accesses['@R']
    
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
            self.fct_candidates = self.handle_att_function(att['identifiers'])
        elif att['type'] == 'EMULATION':
            self.handle_att_emulation(att)

    def handle_att_file(self):
        return True

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
                candidates = self.handle_id_string(id, candidates)
            elif id['type'] == 'bb_graph':
                pass

            if len(candidates) == 0:
                found = False
                Utils.log('fail', f'FUNCTION: \"{id["type"]}\" \"{id["value"]}\": no function matching all the constraints')
                break

        if found:
            Utils.log('success', f'Found a matching function: {hex(candidates[0])}')
            # TODO: handle multiple function still matches

        return candidates

    def handle_att_emulation(self, att):
        if self.fct_candidates == []:
            Utils.log('error', f'No function on which to apply EMULATION...')

        # TODO: get graph path

        # TODO: check that the new graph is equivalent
        # TODO: a 'strict' mode
        #   -> if graph differs stop there and go check for the vuln manually
        #   -> a more permissive option which tries anyway, if it's a big function, maybe the
        #      changes doesn't affect our path and BB ids are the same

        # TODO: apply 'context'

        for fct in self.fct_candidates:
            graph_ref = self.get_graph_from_desc(att['bb_graph_label'])

            for cmd in att['commands']:
                if cmd['cmd'] == 'get_memreads':
                    self.handle_cmd_get_memreads(cmd, att['bb_graph_path'], graph_ref, fct)
                if cmd['cmd'] == 'exec_until':
                    #self.handle_cmd_exec_until()
                    pass

        return True
    
    def handle_cmd_get_memreads(self, obj_cmd, graph_path, graph_ref, addr):
        graph = self.get_graph(addr)

        # TODO: check graphs match
        #Utils.log('debug', graph)
        #Utils.log('debug', '')
        #Utils.log('debug', graph_ref)
        #Utils.log('debug', graph.average_path_length())
        #Utils.log('debug', graph_ref.average_path_length())

        memreads = []
        bbs = self.get_bbs(addr)

        # TODO: get the id in grpah_path right
        for id in graph_path:
            memreads += self.get_memreads(bbs[id]['addr'])
        Utils.log('debug', memreads)

        self.handle_cmd_results(obj_cmd['results'], memreads)

        return True

    def handle_cmd_exec_until(self, obj_cmd, graph_path, graph_ref, addr):
        # TODO: get esil string of the bbs

        # TODO: interpret the string: look for 'keypoints'

        # TODO: emulate until 'keypoint'

        # TODO: handle results

        return True

    def handle_cmd_results(self, obj_results, data_in):
        for result in obj_results:
            if result['type'] == 'reg':
                pass
            elif result['type'] == 'stack':
                pass
            elif result['type'] == 'mem':
                pass
            elif result['type'] == 'callback':
                if result['action'] == 'write':
                    self.r.cmd(f'w {result["value"]} @ {data_in[result["elem_id"]]}')
                    test = self.r.cmd(f'px 8 @ {data_in[result["elem_id"]]}')
                    Utils.log('debug', test)

    def handle_id_string(self, obj_string, candidates):
        result = self.r.cmd(f'iz~{obj_string["value"]}')

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
