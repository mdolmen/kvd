#!/usr/bin/env python3

import r2pipe
import re
import argparse
import inspect
import subprocess
import json

from colorama import Fore, Style, init as colorama_init

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

class VulnObserver():
    def __init__(self, target):
        colorama_init()

        self.options = self.init_options(target)
        self.r = r2pipe.open(target, self.options)

        # TODO: fine tune the analysis depending of the needs for faster load
        self.log('info', 'Analyzing the binary...')

        # TEST: to speed up testing, r2 project feature works \o/
        if 'wifid' in target:
            self.r.cmd('Po wifid_14_1')
        else:
            self.r.cmd('aaa')

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

        # Applies to ELF only, TODO: check that first
        if bin_info['relro'] == 'full':
            options += ['-e', 'bin.cache=true']

        # TODO: check if dyldcache

        return options

    def log(self, type, msg):
        if type == 'error':
            print(f'{Fore.RED}[-] {inspect.stack()[1].function}: {msg}{Style.RESET_ALL}')
            exit(1)
        elif type == 'success':
            print(f'{Fore.GREEN}[+] {msg}{Style.RESET_ALL}')
        elif type == 'info':
            print(f'{Fore.YELLOW}[INFO] {msg}{Style.RESET_ALL}')
        elif type == 'debug':
            print(f'{Fore.MAGENTA}[DEBUG] {msg}{Style.RESET_ALL}')

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
        self.r.cmd(f's {addr}')
        info = self.r.cmdj('afij')

        if len(info) == 0:
            self.log('error', f'no function found containing {hex(addr)}')
        
        return (info[0]['offset'], info[0]['offset']+info[0]['size'])

    def get_bbs(self, addr):
        self.r.cmd(f's {addr}')
        basic_blocks = self.r.cmdj('afbj')
        return basic_blocks

    def get_bb_ids(self, addresses):
        """
        Get basic block IDs containing each address.
        """
        bb_ids = []

        for addr in addresses:
            start, end = self.get_fct_range(addr)
            bbs = self.get_bbs(addr)

            index = 0
            for bb in bbs:
                if addr >= bb['addr'] and addr <= bb['addr']+bb['size']:
                    bb_ids.append(index)
                index += 1

        return bb_ids
    
    def check_description(self, desc):
        """
        Check the format correctness of a vuln description file.
        """
        assert len(desc['metadata']) != 0, "Vuln description error: empty metadata"
        assert len(desc['revisions']) != 0, "Vuln description error: empty revisions, nothing to look for"
        # TODO: ...
        self.log('success', 'Description OK')

    def handle_attribute(self, att):
        """
        Handle an attribute from the vuln that should be present in the target we test.
        """
        if att['type'] == 'FILE':
            self.handle_att_file()
        elif att['type'] == 'FUNCTION':
            self.handle_att_function()
        elif att['type'] == 'EMULATION':
            self.handle_att_emulation(att)

    def handle_att_file(self):
        return True

    def handle_att_function(self):
        return True

    def handle_att_emulation(self, att):
        # TODO: get graph path from bb_id_start to bb_id_end

        # TODO: apply 'context'

        for cmd in att['commands']:
            self.handle_obj_cmd(cmd)

        return True
    
    def handle_obj_cmd(self, obj):
        if obj['cmd'] == 'get_memreads':
            self.cmd_get_memreads()
        if obj['cmd'] == 'exec_until':
            self.cmd_exec_until()

    def cmd_get_memreads(self):
        pass

    def cmd_exec_until(self):
        pass
    
    def search_vuln(self, desc_file):
        desc = json.load(desc_file)
        self.check_description(desc)

        for rev in desc['revisions']:
            for att in rev['attributes']:
                self.handle_attribute(att)
            # TODO: print conclusion for revision, 'found' or 'maybe patched'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--bb-ids', nargs='*',
                        help='Get the basic block IDs corresponding to the given addresses')
    parser.add_argument('-s', '--search', type=argparse.FileType('r'),
                        help='JSON file describing a vulnerability to look for')
    parser.add_argument('-c', '--check', type=argparse.FileType('r'),
                        help='Check the correctness of a description file')
    args = parser.parse_args()

    # TODO: arg
    target = "ls"

    vo = VulnObserver(target)

    # TEST: run it with: 0x77AE 0x7890

    if args.bb_ids:
        addresses = [int(a, 16) for a in args.bb_ids]
        bb_ids = vo.get_bb_ids(addresses)

        # TODO: output in json ready to be copy/pasted in a description file
        for i in range(len(args.bb_ids)):
            print(f"Basic block ID of {hex(addresses[i])}: {bb_ids[i]}")
        exit(0)

    if args.check:
        desc = json.load(desc_file)
        vo.check_description()

    if args.search:
        vo.search_vuln(args.search)
