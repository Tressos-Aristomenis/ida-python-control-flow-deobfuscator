from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def ida_prettify(addr):
    return f'.text:{addr:9x}\t{GetDisasm(addr)}'

def capstone_prettify(bytecode):
    buf = []
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    for d in cs.disasm(bytecode, 0x00):
        buf.append(f'0x{d.address:x} :\t{d.mnemonic}\t\t{d.op_str}')
    return buf

class Deobfuscator:
    def __init__(self, oep):
        self.oep = oep
        self.visited = []
        self.to_visit = []
        # http://unixwiz.net/techtips/x86-jumps.html
        self.conditional_jumps = ['jo', 'jno', 'js', 'jns', 'je', 'jne', 'jz', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz']
        self.returns = ['ret', 'retn', 'retf']
        # false positive
        self.black_list = [0x18002ad20, 0x180032bc5, 0x180049730, 0x1800497a8, 0x180051134, 0x180065720, 0x1800335b1, 0x18005fd3c, 0x1800648a4, 0x180058858, 0x18000854c]

    def get_mnemonic(self, addr):
        return print_insn_mnem(addr)

    def get_instruction_size(self, addr):
        return DecodeInstruction(addr).size
    
    def disassemble_line(self, addr):
        return GetDisasm(addr)
    
    def fetch_jmp_address(self, addr):
        return get_operand_value(addr, 0)
    
    def assemble_line(self, addr):
        return get_bytes()

    def is_visited(self, addr):
        return addr in self.visited

    def check_opcode(self, addr):
        return get_bytes(addr, 1)
    
    def assemble_line(self, addr):
        return get_bytes(addr, self.get_instruction_size(addr))

    def callee_functions(self):
        callee = [self.oep]  # include oep
        funcs = [f for f in Functions() if f not in self.black_list]
        for f in funcs:
            x = list(XrefsTo(f))
            if any(['call' in self.disassemble_line(i.frm) for i in x]):
                callee.append(f)
        return callee
    
    def is_call_to_existing_function(self, mnem, addr):
        return mnem == 'call' and self.check_opcode(addr) == b'\xe8'

    def is_jump_to_existing_location(self, mnem, addr):
        return mnem == 'jmp' and self.check_opcode(addr) == b'\xe9'

    def address_needs_fix(self, mnem, addr):
        return self.is_jump_to_existing_location(mnem, addr) or self.is_call_to_existing_function(mnem, addr) or mnem in self.conditional_jumps

    def deobfuscate(self, addr):
        while True:
            if self.is_visited(addr):
                break

            mnem = self.get_mnemonic(addr)

            if mnem in self.returns:
                self.deobfuscated_chain.append(addr)
                break

            if mnem.startswith('j') or self.is_call_to_existing_function(mnem, addr):
                if self.check_opcode(addr) == b'\xff':
                    # handle most edge cases such as jumps to memory operands
                    # this should be equivalent to "ret"
                    self.visited.append(addr)
                    self.deobfuscated_chain.append(addr)
                    break

                jmp_addr = self.fetch_jmp_address(addr)

                if mnem == 'call':
                    if jmp_addr not in self.to_visit:
                        self.to_visit.append(jmp_addr)

                elif mnem in self.conditional_jumps:
                    # if the conditional jmp lands on a jmp instruction
                    # include it in the final chain as it is the bridge between the two blocks
                    if self.get_mnemonic(jmp_addr) == 'jmp':
                        self.deobfuscated_chain.append(jmp_addr)

                    self.to_visit.insert(0, jmp_addr)

                else:
                    # normal jmp
                    if self.is_visited(jmp_addr):
                        # loop found
                        # no need to do nothing
                        # we handle the case for visited addresses above
                        self.deobfuscated_chain.append(addr)

                    self.visited.append(addr)
                    addr = jmp_addr
                    continue
            
            self.visited.append(addr)
            self.deobfuscated_chain.append(addr)

            # move to next instruction
            addr += self.get_instruction_size(addr)
        
        if not self.to_visit:
            return

        branch = self.to_visit.pop(0)
        self.deobfuscate(branch)

    def fix_jumps_and_calls(self):
        self.bytecode = b''
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        for curr_addr in self.deobfuscated_chain:
            mnem = self.get_mnemonic(curr_addr)

            if self.address_needs_fix(mnem, curr_addr):
                # need to fix jump address
                old_jmp_addr = self.fetch_jmp_address(curr_addr)
                new_jmp_addr  = self.new_address_mapping[old_jmp_addr]
                new_curr_addr = self.new_address_mapping[curr_addr]
                new_relative_addr = new_jmp_addr - new_curr_addr
                _asm = bytes(ks.asm(f'{mnem} {new_relative_addr}')[0])
                if self.get_instruction_size(curr_addr) > len(_asm):
                    # if assembled opcodes are less than in the original binary
                    # add some NOPs
                    # this happens because in the original binary, the distance
                    # between instructions is large. Thus, for example,
                    # the opcodes of a cond jump would be "0f 84 xx xx xx xx"
                    # whereas now the equivalent would be "75 xx"
                    _asm += b'\x90' * (self.get_instruction_size(curr_addr) - len(_asm))
                self.bytecode += _asm
                continue
            
            self.bytecode += self.assemble_line(curr_addr)
        
        if EXPORT_DEOBFUSCATED_SHELLCODE:
            with open(PATH + DEOBFUSCATED_SHELLCODE_FILENAME, 'wb') as f:
                f.write(self.bytecode)
            print(f'[+] Deobfuscated shellcode written to "{DEOBFUSCATED_SHELLCODE_FILENAME}" successfully.')

        if EXPORT_NEW_DEOBFUSCATED_DISASSEMBLY_CAPSTONE_FORMATTED:
            prettified_buffer = capstone_prettify(self.bytecode)
            with open(PATH + NEW_DISASSEMBLY_FILENAME, 'w') as f:
                f.write('\n'.join(prettified_buffer))
            print(f'[+] New deobfuscated disassembly written to "{NEW_DISASSEMBLY_FILENAME}" successfully.')

    def calculate_new_addresses(self):
        self.new_address_mapping = {}
        new_addr = 0

        for old_addr in self.deobfuscated_chain:
            sz = self.get_instruction_size(old_addr)
            self.new_address_mapping[old_addr] = new_addr
            new_addr += sz

        print('[+] Calculated and mapped the new addresses to the old ones.')

    def deobfuscate_init(self, method):
        self.deobfuscated_chain = []

        if method == 1:
            for func in self.callee_functions():
                self.deobfuscate(func)
        
        elif method == 2:
            self.deobfuscate(self.oep)

        elif method == 3:
            assert SPECIFIC_FUNCTION, 'You must specify where you want to start deobfuscating from.'
            self.deobfuscate(SPECIFIC_FUNCTION)
        
        else:
            exit('[-] Not implemented yet :-(')

        if EXPORT_OLD_DEOBFUSCATED_DISASSEMBLY_IDA_FORMATTED:
            prettified_buffer = list(map(ida_prettify, self.deobfuscated_chain))
            with open(PATH + OLD_DISASSEMBLY_FILENAME, 'w') as f:
                f.write('\n'.join(prettified_buffer))
            print(f'[+] Old deobfuscated disassembly written to "{OLD_DISASSEMBLY_FILENAME}" successfully.')


########################## MAIN CONFIGURATION ##########################

PATH = 'D:\\CTFs\\flare-on\\2023\\13_y0da\\y0da\\'
############################################
EXPORT_OLD_DEOBFUSCATED_DISASSEMBLY_IDA_FORMATTED = True
OLD_DISASSEMBLY_FILENAME = 'old-deobf-ida-disasm.asm'
############################################
EXPORT_DEOBFUSCATED_SHELLCODE = True
DEOBFUSCATED_SHELLCODE_FILENAME = 'y0da_deobfuscated.bin'
############################################
EXPORT_NEW_DEOBFUSCATED_DISASSEMBLY_CAPSTONE_FORMATTED = True
NEW_DISASSEMBLY_FILENAME = 'new-deobf-capstone-disasm.asm'

# Below you can choose where the deobfuscator should start working

METHODS = {
    1 : 'ALL_CALLEE_FUNCTIONS', # default
    2 : 'FROM_OEP',
    3 : 'FROM_SPECIFIC_FUNCTION'
}

SELECTED_METHOD = 1



OEP = 0x180032701     # edit once!
SPECIFIC_FUNCTION = 0 # define only if you select the third method

########################################################################

if __name__ == '__main__':
    deobfuscator = Deobfuscator(OEP)
    print('='*40)
    deobfuscator.deobfuscate_init(SELECTED_METHOD)
    deobfuscator.calculate_new_addresses()
    deobfuscator.fix_jumps_and_calls()
    print('='*40)