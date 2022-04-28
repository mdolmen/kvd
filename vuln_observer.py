#!/usr/bin/env python3

import r2pipe
import re
import argparse
import inspect
import subprocess
import json
import os

from colorama import Fore, Style, init as colorama_init
from tempfile import NamedTemporaryFile
from igraph import Graph
from base64 import b64encode, b64decode

"""
ESIL doc: https://book.rada.re/disassembling/esil.html
"""

INFO  = False
DEBUG = False

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
            if not INFO:
                return
            print(f'{Fore.YELLOW}[*]{Style.RESET_ALL} {msg}')
        elif type == 'debug':
            if not DEBUG:
                return
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
    def __init__(self, target, is_dyld=False):
        colorama_init()

        self.target = target
        self.desc = None
        self.fct_candidates = dict()
        self.pc = 'pc'
        self.sp = 'sp'
        self.options = self.init_options(self.target, is_dyld)
        self.r = r2pipe.open(self.target, self.options)

        # TODO: fine tune the analysis depending of the needs for faster load

        Utils.log('debug', f'target = {self.target}')
        Utils.log('debug', f'options = {self.options}')

        # TEST: to speed up testing, r2 project feature works \o/
        if 'wifid_14.1' in self.target:
            Utils.log('success', 'Opening project...')
            self.r.cmd('Po wifid_14_1')
        else:
            Utils.log('success', 'Analyzing the binary...')
            self.r.cmd('aaa')

        # TODO: once analysis done, automatically save the project

        # Init ESIL
        self.r.cmd('aei')
        self.r.cmd('aeim')
        self.r.cmd('e asm.esil=true')

    def init_options(self, target, is_dyld):
        """
        Use rabin2 to get information about the binary to determine what we have to deal with.
        """
        options = []

        if is_dyld:
            os.environ["R_DYLDCACHE_FILTER"] = target
            return ['-e', 'bin.usextr=false']

        bin_info = subprocess.check_output(['rabin2', '-Ij', target])
        bin_info = json.loads(bin_info)
        bin_info = bin_info['info']

        if bin_info['arch'] == 'arm':
            pass
        elif bin_info['arch'] == 'x86':
            self.pc == 'rip'
            self.sp == 'rsp'

        if bin_info['bintype'] == 'mach0':
            pass
        elif bin_info['bintype'] == 'elf':
            if bin_info['relro'] == 'full':
                options += ['-e', 'bin.cache=true']

        return options

    def esil_get_nb_branches(self, estr):
        """
        Returns the number of times PC gets changed (branch, jmp, call).

        estr : The ESIL string in which to search for
        """
        calls = [m.start() for m in re.finditer(f'{self.pc},=', estr)]
        return len(calls)

    def esil_emulate(self, start, kp, until):
        """
        Emulate from 'start' to 'kp' as many times as indicated by 'until'.

        start   : addr at which to start the emulation
        kp      : an ESIL expression (i.e. 'pc,=' for a branch)
        until   : the occurenc of 'kp' at which to stop

        Returns a JSON object representing the register state.
        """
        self.r.cmd(f's {start}')
        self.r.cmd(f'aeip')

        for i in range(until+1):
            self.r.cmd(f'aesou {kp}')

        return self.r.cmdj('aerj')

    def get_fct_range(self, addr):
        """
        Returns start and end address of the function containing addr.
        """
        info = self.r.cmdj(f'afij @ {addr}')

        if len(info) == 0:
            Utils.log('error', f'no function found containing {hex(addr)}')
        
        return (info[0]['offset'], info[0]['offset']+info[0]['size'])

    def get_disas(self, addr, size):
        """
        Returns a JSON object representing the disasembly for the given range.

        addr: start address
        size: number of bytes to disassemble
        """
        return self.r.cmdj(f'pDj {size} @ {addr}')

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

    def get_bb_to_esil_str(self, bb):
        """
        Returns the ESIL string of all the instructions in the given bascic block.
        """
        disas = self.get_disas(bb['addr'], bb['size'])
        estr = "".join(inst["esil"] for inst in disas)
        return estr

    def get_memreads(self, addr):
        """
        Returns the memory reads done at the basic block containing 'addr'.
        """
        reg_mem_accesses = self.r.cmdj(f'aeabj @ {addr}')
        return reg_mem_accesses['@R']

    def get_string(self, s):
        return self.r.cmd(f'iz~{s}')

    def get_symbol(self, s, is_function):
        """
        Returns the address of the given symbol.
        """
        result = self.r.cmd(f'is~{s}')
        result = ' '.join(result.split(' ')).split()
        addr = 0

        if result:
            sym_addr = int(result[2], 16)
            sym_type = result[4]
            sym_name = result[-1]
            Utils.log('debug', f'sym_type = {sym_type}, sym_name = {sym_name}')

            if is_function and sym_type != "FUNC":
                addr = 0
            elif sym_name == s:
                addr = sym_addr

        return addr

    def get_method(self, classname, method):
        """
        Returns the address of the 'method' in 'classname'.
        """
        classes = self.r.cmdj(f'icj')
        addr = 0

        Utils.log('debug', f'Looking for method "{method}" in class "{classname}"')
        for c in classes:
            if c['classname'] == classname:
                for m in c['methods']:
                    if m['name'] == method:
                        addr = m['addr']

        return addr
    
    def get_graph(self, addr, save=False, dest=None):
        """
        Returns the GML graph of the function containing 'addr'.
        Can save the GML output from r2 to a file.
        """
        start, _ = self.get_fct_range(addr)
        tmp = None

        if save:
            gname = f'{self.target}_{hex(addr)}.gml'
        else:
            tmp = NamedTemporaryFile()
            gname = tmp.name
            Utils.log('debug', gname)

        if dest:
            gname = dest

        # 'agfg' command doesn't have a JSON option for output and the JSON format of the graph is
        # not as concise as the GML one.
        self.r.cmd(f'agfg @ {addr} > {gname}')
        Utils.log('success', f'Basic block graph for {hex(addr)} written to {gname}')

        # Create GML graph from file
        g = Graph()
        graph = g.Read_GML(gname)
        Utils.log('debug', graph)

        if tmp:
            tmp.close()

        return graph

    def get_graph_paths(self, g, start, end):
        return g.get_all_simple_paths(start, to=end)

    def get_saved_graph(self, filepath):
        """
        Returns an igraph object from a file containing a graph in GML format.
        """
        if not os.path.exists(filepath):
            Utils.log('error', f'{filepath} does not exists')

        g = Graph()
        graph = g.Read_GML(filepath)

        return graph

    def cmp_graph(self, a, b):
        """
        Check if graph 'b' is the same as 'a'.
        """
        return b.isomorphic(a)

    def read_at(self, addr, length):
        return bytes(self.r.cmdj(f'pxj {length} @ {addr}'))

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
        check = True

        if att['type'] == 'FUNCTION':
            check = self.handle_att_function(att['identifiers'], att['fct_id'])
        elif att['type'] == 'EMULATION':
            check = self.handle_att_emulation(att)

        return check

    def handle_att_function(self, identifiers, fct_id):
        """
        Look for the function matching the constraints described in 'identifiers'.
        Return the start address of all the functions matching.
        """
        Utils.log('info', 'Searching for a FUNCTION...')

        # Potential function matching the constraints
        candidates = []
        found = True

        for id in identifiers:
            Utils.log('debug', f'type = {id["type"]}, name = \"{id["name"]}\"')
            if id['type'] == 'symbol':
                candidates = self.handle_id_symbol(id, candidates)
            elif id['type'] == 'string':
                candidates = self.handle_id_string(id, candidates)
            elif id['type'] == 'bb_graph':
                # TODO: parse all function looking for a specific graph
                pass

            Utils.log('debug', candidates)

            if len(candidates) == 0:
                found = False
                Utils.log('fail', f'FUNCTION: \"{id["type"]}\" \"{id["name"]}\": no function matching all the constraints')
                break

        self.fct_candidates[fct_id] = candidates

        if found:
            Utils.log('success', f'Found matching function(s): {[hex(c) for c in candidates]}')

        return found

    def handle_att_emulation(self, att):
        Utils.log('info', 'Applying EMULATION logic...')
        check = True

        if self.fct_candidates[att['fct_id']] == []:
            Utils.log('error', f'No function on which to apply EMULATION...')

        # TODO: apply 'context'

        for i, fct in enumerate(self.fct_candidates[att['fct_id']]):
            graph_match = True

            # Check that this function BB graph matches the reference one
            for filepath in att['bb_graph_filepaths']:
                graph_ref = self.get_saved_graph(filepath)
                graph_fct = self.get_graph(fct)
                graph_match = self.cmp_graph(graph_ref, graph_fct)
                if graph_match:
                    break

            if not graph_match:
                Utils.log('fail', f'Difference in basic block graphs for function holding {hex(fct)}')
                check = False
                break

            for cmd in att['commands']:
                if cmd['cmd'] == 'get_memreads':
                    check = self.handle_cmd_get_memreads(cmd, att['bb_graph_path'], fct)
                if cmd['cmd'] == 'exec_until':
                    check = self.handle_cmd_exec_until(cmd, att['bb_graph_path'], fct)

        return check
    
    def handle_cmd_get_memreads(self, obj_cmd, graph_path, addr):
        memreads = []
        bbs = self.get_bbs(addr)

        for id in graph_path:
            Utils.log('debug', f'addr = {bbs[id]["addr"]}')
            memreads += self.get_memreads(bbs[id]['addr'])

        return self.handle_cmd_results(obj_cmd['results'], memreads)

    def handle_cmd_exec_until(self, obj_cmd, graph_path, addr):
        bbs = self.get_bbs(addr)
        kp_type = obj_cmd['keypoints']['type']
        kp_expected = obj_cmd['keypoints']['expected']
        kp_stop_at = obj_cmd['keypoints']['position']

        estr = ""
        for id in graph_path:
            estr += self.get_bb_to_esil_str(bbs[id])

        # Check number of keypoints is as expected
        keypoint = ''
        nb_keypoints = 0
        if kp_type == 'branch':
            keypoint = f'{self.pc},='
            nb_keypoints = self.esil_get_nb_branches(estr)
        #elif kp_type == 'TODO: implement more kp':
        #    pass

        if nb_keypoints != kp_expected:
            Utils.log('error',
                      f'Number of "{kp_type}" ({nb_keypoints}) differs from what was expected ({kp_expected})!')

        Utils.log('debug', f'start = {bbs[graph_path[0]]["addr"]}, kp = {keypoint}, stop_at = {kp_stop_at}')
        regs = self.esil_emulate(bbs[graph_path[0]]['addr'], keypoint, kp_stop_at)

        return self.handle_cmd_results(obj_cmd['results'], regs)

    def handle_cmd_results(self, obj_results, data_in):
        check = True

        while check:
            for result in obj_results:
                if result['type'] == 'reg':
                    pass

                elif result['type'] == 'stack':
                    Utils.log('info', 'Checking stack state...')
                    sp = data_in[self.sp]
                    if result['operand'] not in ['==', '!=', '<', '>', '<=', '>=']:
                        Utils.log('error', 'Nope, not doing that.')
                    if result['deref']:
                        addr = sp + result['offset']
                        expected = bytes.fromhex(result['value'])
                        length = len(expected)
                        data = self.read_at(addr, length)
                        op = result['operand']
                        Utils.log('debug', f'addr = {hex(addr)}, operand = {op}, data = {data}')
                        check = eval(f'{data} {op} {expected}')
                    else:
                        expected = bytes.fromhex(result['value'])
                        data = sp + result['offset']
                        operand = result["operand"]
                        Utils.log('debug', f'data = {data}, operand = {operand}, expected = {expected}')
                        check = eval(f'{data} {operand} {expected}')

                elif result['type'] == 'mem':
                    pass

                elif result['type'] == 'callback':
                    Utils.log('info', 'Applying callback...')
                    if result['action'] == 'write':
                        dest = data_in[result["elem_id"]]
                        data = result["value"]
                        Utils.log('debug', f'Writing {data} at {hex(dest)}')
                        self.r.cmd(f'wx {data} @ {dest}')

            break

        return check

    def handle_id_string(self, obj_string, candidates):
        result = self.get_string(obj_string["name"])

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
    
    def handle_id_symbol(self, obj_symbol, candidates):
        Utils.log('debug', f'Looking for symbol {obj_symbol["name"]}')
        new_candidates = []

        if obj_symbol['class'] != '':
            addr = self.get_method(obj_symbol['class'], obj_symbol['name'])
            if addr:
                new_candidates.append(addr)
        else:
            addr = self.get_symbol(obj_symbol['name'], obj_symbol['is_function'])
            if addr:
                new_candidates.append(addr)

        if len(candidates) == 0:
            # No other result yet, it's the first constraint being tested.
            return new_candidates

        candidates = Utils.present_in_both(candidates, new_candidates)

        return candidates

    def search_vuln(self, desc_file):
        vulnerable = True
        self.desc = json.load(desc_file)
        self.check_description(self.desc)
        codename = self.desc["metadata"]["codename"]

        for rev in self.desc['revisions']:
            for att in rev['attributes']:
                if not self.handle_attribute(att):
                    vulnerable = False
                    break

        if vulnerable:
            Utils.log('success', f'{codename} found!')
        else:
            Utils.log('fail', f'{codename} may be patched. One {att["type"]} does not match...')

        return vulnerable

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
    parser.add_argument('-d', '--dyld',
                        help='The dyldcache in which to look for the target')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()

    INFO = (args.verbose > 0)
    DEBUG = (args.verbose > 1)

    if args.dyld:
        target = args.dyld
    else:
        target = args.target
    is_dyld = (args.dyld != 0)

    vo = VulnObserver(target, is_dyld)

    if args.extract:
        # TODO: get_bb_ids
        # TODO: get_graph
        # TODO: get_graph_path between 2 bb_id
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

        for addr in addresses:
            vo.get_graph(addr, save=True)

    if args.check:
        self.desc = json.load(desc_file)
        vo.check_description()

    if args.search:
        vo.search_vuln(args.search)
