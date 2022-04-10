import json
import os
import ida_entry
import ida_ua
import idaapi
import idautils
import idc
import ida_xref
import ida_segment
import ida_bytes
import pydevd_pycharm

PE_OFFSET = 0x3c
IMAGE_SUBSYSTEM_EFI_APPLICATION = 0xa
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 0xb
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 0xc
RUNTIME_SERVICES_OFFSET_x64 = 0x58
RUNTIME_SERVICES_OFFSET_x86 = 0x38
REG_RAX = 0
REG_RCX = 1
REG_SP = 4
VZ = 0x5A56
RUNTIME_SERVICES = {
    "GetVariable": [0x48, 0x30]
}
DEBUG = False

class Analyser:
    def __init__(self):
        # wait until fully analysed
        idc.Wait()
        self.arch = get_file_arch()
        header = get_header()
        if len(header) != 0:
            self.file_type = check_file_type(header, self.arch)
        if not self.file_type:
            print('[ERROR] Unsupported file type')
            idc.Exit(0)
        if not (self.arch == 'x86' or self.arch == 'x64'):
            print('[ERROR] Unsupported architecture')
            idc.Exit(0)
        self.grt_list = []

    # get *gRT
    def get_runtime_services_table(self):
        RT_OFFSET = RUNTIME_SERVICES_OFFSET_x64
        if self.arch == "x86":
            RT_OFFSET = RUNTIME_SERVICES_OFFSET_x86
        # get the start code segment
        code = list(idautils.Functions())[0]
        start = idc.get_segm_start(code)
        end = idc.get_segm_end(code)
        ea = start
        print("[Info] Search from " + hex(start) + " to " + hex(end))
        while ea <= end:
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, ea)
            # eg. mov rax,[rdx+0x58] 0x58 is the offset of gRT for gST(EFI_SYSTEM_TABLE)
            if idc.print_insn_mnem(ea) == "mov" and idc.get_operand_type(ea, 1) == ida_ua.o_displ and \
                    insn.ops[1].phrase != REG_SP and idc.get_operand_type(ea, 0) == ida_ua.o_reg and \
                    insn.ops[1].addr == RT_OFFSET:
                rt_register = insn.ops[0].reg
                for i in range(10):
                    ea = idc.next_head(ea)
                    ida_ua.decode_insn(insn, ea)
                    if idc.print_insn_mnem(ea) == "mov" and idc.get_operand_type(ea, 0) == ida_ua.o_reg and \
                            idc.get_operand_type(ea, 1) == ida_ua.o_imm:
                        grt_addr = idc.get_operand_value(ea, 1)
                        phrase_reg = insn.ops[0].phrase
                        next_ea = idc.next_head(ea, idaapi.BADADDR)
                        next_insn = ida_ua.insn_t()
                        ida_ua.decode_insn(next_insn, next_ea)
                        if idc.print_insn_mnem(next_ea) == "mov" \
                                and idc.get_operand_type(next_ea, 0) == ida_ua.o_phrase \
                                and next_insn.ops[0].phrase == phrase_reg \
                                and idc.get_operand_type(next_ea, 1) == ida_ua.o_reg \
                                and next_insn.ops[1].reg == rt_register:
                            print("[Info] Get *gRT ! address is ", hex(grt_addr))
                            self.grt_list.append(grt_addr)
                            break
                    # eg. mov cs:qword_6420,rax
                    if idc.print_insn_mnem(ea) == "mov" and idc.get_operand_type(ea, 1) == ida_ua.o_reg \
                            and idc.get_operand_type(ea, 0) == ida_ua.o_mem and insn.ops[1].reg == rt_register:
                        grt_addr = insn.ops[0].addr
                        self.grt_list.append(grt_addr)
                        print("[Info] Get *gRT ! address is ", hex(grt_addr))
                        break
            ea = idc.next_head(ea)

    def get_get_variable_services(self):
        print("[Info] Using xref to get all services")
        fuzz_vars = []
        for grt_address in self.grt_list:
            # get xref for each *gRT
            xrefs = get_xrefs(grt_address)
            for ea in xrefs:
                insn = ida_ua.insn_t()
                ida_ua.decode_insn(insn, ea)
                # eg. mov     rax, cs:gRT
                if not (idc.print_insn_mnem(ea) == "mov"
                        and (insn.ops[1].addr == grt_address or insn.ops[1].value == grt_address)):
                    continue
                next_ea = ea
                rt_reg = insn.ops[0].reg
                service_offset = idaapi.BADADDR
                for i in range(16):
                    next_ea = idc.next_head(next_ea, idaapi.BADADDR)
                    ida_ua.decode_insn(insn, next_ea)
                    if idc.print_insn_mnem(next_ea) == "mov" and idc.get_operand_type(next_ea, 1) == ida_ua.o_displ \
                            and insn.ops[1].reg == rt_reg and insn.ops[1].addr:
                        service_offset = insn.ops[1].addr
                    # eg. call qword ptr [rax+48h] 0x48 is the offset of GetVariable service
                    if insn.itype == idaapi.NN_callni and insn.ops[0].reg == REG_RAX:
                        if insn.ops[0].addr:
                            service_offset = insn.ops[0].addr
                        offset = RUNTIME_SERVICES["GetVariable"][0]
                        if self.arch == "x86":
                            offset = RUNTIME_SERVICES["GetVariable"][1]
                        if service_offset == offset:
                            print("RUNTIME SERVICES: " + "GetVariable" + " found at " + hex(next_ea))
                            if self.arch == "x64":
                                var_value = get_variable_value_x64(next_ea)
                                if var_value != "":
                                    fuzz_vars.append(
                                        {"Arch": "x64", "Address": hex(next_ea), "Variable": var_value})
                            elif self.arch == "x86":
                                fuzz_vars.append({"Arch": "x86", "Address": hex(next_ea)})
                            break
        return fuzz_vars


def get_variable_value_x64(ea):
    prev_ea = ea
    for i in range(6):
        prev_ea = idc.prev_head(prev_ea)
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, prev_ea)
        if idc.print_insn_mnem(prev_ea) == "lea" and idc.get_operand_type(prev_ea, 0) == ida_ua.o_reg \
                and insn.ops[0].reg == REG_RCX and idc.get_operand_type(prev_ea, 1) == ida_ua.o_mem:
            var_value = idc.get_strlit_contents(idc.get_operand_value(prev_ea, 1), -1, 1)
            print("variable value is: " + var_value)
            return var_value
    return ""


def get_xrefs(address):
    xref = ida_xref.get_first_dref_to(address)
    xrefs = []
    while xref != idaapi.BADADDR:
        xrefs.append(xref)
        xref = ida_xref.get_next_dref_to(address, xref)
    return xrefs


# check if the file loaded is UEFI application or driver. Skip if the file is Pei
def check_file_type(header, arch):
    if "UEFI" in idaapi.get_file_type_name():
        return True
    temp = ida_segment.get_segm_by_name("HEADER")
    if temp is None:
        return False
    signature = ida_bytes.get_wide_word(temp.start_ea)
    # Pei file
    if signature == VZ and arch == "x86":
        return False

    if len(header) < PE_OFFSET + 1:
        return False
    PE_POINTER = header[PE_OFFSET]
    if len(header) < PE_POINTER + 0x5d:
        return False
    subsystem = header[PE_POINTER + 0x5c]
    return (subsystem == IMAGE_SUBSYSTEM_EFI_APPLICATION
            or subsystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
            or subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER)


# get system table address (not used for now)
def get_system_table_x64():
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        for j in range(16):
            if idc.print_insn_mnem(ea) == "mov" and idc.get_operand_type(ea, 1) == ida_ua.o_reg \
                    and idc.get_operand_value(ea, 1) == 2 and idc.get_operand_type(ea, 0) == ida_ua.o_mem:
                print("find system table:", idc.get_operand_value(ea, 0))
                break
            ea = idc.next_head(ea)


# get image handle address (not used for now)
def get_image_handle_x64():
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        for j in range(8):
            if idc.print_insn_mnem(ea) == "mov" and idc.get_operand_type(ea, 1) == ida_ua.o_reg \
                    and idc.get_operand_value(ea, 1) == 1 and idc.get_operand_type(ea, 0) == ida_ua.o_mem:
                print("find image handle:", idc.get_operand_value(ea, 0))
                break
            ea = idc.next_head(ea)


# get file type. skip Pei file
def get_file_type(arch):
    filetype = idaapi.get_file_type_name()
    if "UEFI" in filetype:
        return True
    header = ida_segment.get_segm_by_name("HEADER")
    if header is None:
        return False
    signature = ida_bytes.get_wide_word(header.start_ea)
    # Pei file
    if signature == VZ and arch == "x86":
        return False


# get the arch of the file
def get_file_arch():
    filetype = idaapi.get_file_type_name()
    if '80386' in filetype:
        return "x86"
    elif "AMD64" in filetype:
        return "x64"
    else:
        return "unSupported"


# get the header bytes of the file
def get_header():
    header = ida_segment.get_segm_by_name("HEADER")
    if header is not None:
        return bytearray(
            [idc.get_wide_byte(ea) for ea in range(header.start_ea, header.end_ea)])
    return bytearray(b'')


if __name__ == '__main__':
    if DEBUG:
        pydevd_pycharm.settrace('localhost', port=12345, stdoutToServer=True, stderrToServer=True)
    analyser = Analyser()
    analyser.get_runtime_services_table()
    variable_list = analyser.get_get_variable_services()
    file_name = idaapi.get_input_file_path()
    file_name = file_name.split("/")[-1]
    log_path = os.path.join(os.path.dirname(__file__), "logs", "{}_log.txt".format(file_name))
    if variable_list:
        with open(log_path, 'wb') as f:
            f.write(json.dumps(variable_list).encode())
    idc.Exit(0)
