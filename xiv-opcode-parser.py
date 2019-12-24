"""
IDA Script to parse the ZoneDownHandler and generate a schema of it to identify packets cross-patch.
"""

import ida_search
import ida_ida
import idautils
import ida_idaapi
import idc
import ida_funcs
import ida_bytes
import idaapi
import ida_name

import json

from PyQt5.Qt import QApplication

main_jumptable = ida_idaapi.BADADDR

def log(str, indent=0):
    print('[FFXIV Opcode Parser] %s%s' % ('  ' * indent, str))

def set_clipboard(data):
    QApplication.clipboard().setText(data)

def set_clipboard_json(data):
    set_clipboard(json.dumps(data, indent=2, separators=(',', ':')))
    log('copied parsed data to clipboard')

def find_pattern(pattern):
    return ida_search.find_binary(ida_ida.cvar.inf.omin_ea, ida_ida.cvar.inf.omax_ea, pattern, 16, ida_search.SEARCH_DOWN)

def get_executable_watermark():
    rev_ea = find_pattern('48 8D 0D ? ? ? ? 45 33 F6 41 8B DE')

    ea = idc.GetOperandValue(rev_ea, 1)

    return idc.GetString(ea, -1, idc.ASCSTR_C)

def get_clean_rev(rev_str):
    return rev_str.replace('ff14', '').replace('/', '').replace('*', '')


def find_switch(func_ea):
    # get all chunks that belong to a function, because apparently they're not contiguous or some shit
    for (start_ea, end_ea) in idautils.Chunks(func_ea):
        for head in idautils.Heads(start_ea, end_ea):
            switch = idaapi.get_switch_info_ex(head)

            if switch != None:
                log('found switch @ %x, cases: %d' % (head, switch.get_jtable_size()))
                return (head, switch)

    return (None, None)

def find_block(ea, blocks):
    for block in blocks:
        if block.startEA == ea:
            return block

def ea_to_rva(ea):
    return ea - idaapi.get_imagebase()

def get_bytes_str(start_ea, end_ea):
    size = end_ea - start_ea

    bytes = []
    for ea in range(start_ea, end_ea):
        b = '{:02x}'.format(ida_bytes.get_byte(ea))
        bytes.append(b)

    return ' '.join(bytes)

def get_func_name(ea):
    name = ida_funcs.get_func_name(ea)
    demangled = ida_name.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN))

    return demangled or name

def postprocess_func(fn, depth = 0):
    func = {
        'ea': fn.startEA,
        'rva': ea_to_rva(fn.startEA),
        'body': get_bytes_str(fn.startEA, fn.endEA)
    }

    # total aids
    switch_ea, switch = find_switch(fn.startEA)

    if switch and switch_ea != main_jumptable:
        sw = func['switch'] = {}

        res = idaapi.calc_switch_cases(switch_ea, switch)
        
        case_ids = []
        for case in res.cases:
            for i in case:
                case_ids.append(int(i))

        sw['cases'] = [i for i in set(case_ids)]

    else:
        func['switch'] = None

    return func

def process_func(func, start_ea, end_ea):
    for head in idautils.Heads(start_ea, end_ea):
        flags = idaapi.getFlags(head)
        if idaapi.isCode(flags):

            mnem = idc.GetMnem(head)

            if mnem == 'call' or mnem == 'jmp':
                op_ea = idc.GetOperandValue(head, 0)
                fn = ida_funcs.get_func(op_ea)

                if fn:
                    fn_info = postprocess_func(fn)

                    if fn_info:
                        func['calls'][get_func_name(op_ea)] = fn_info

def process_case(case, id):
    func = case['func'] = {}
    body = func['body'] = get_bytes_str(case['start_ea'], case['end_ea'])
    func['calls'] = {}

    process_func(func, case['start_ea'], case['end_ea'])



def run():
    func_ea = find_pattern('48 89 74 24 ? 57 48 83 EC 50 8B F2 49 8B F8')
    output = {}

    output['rev'] = get_executable_watermark()
    output['clean_rev'] = get_clean_rev(output['rev'])

    if func_ea == ida_idaapi.BADADDR:
        log('couldn''t find server opcode handler')
        return

    func_end_ea = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    output['size'] = func_size = func_end_ea - func_ea

    log('found opcode handler @ %x, end: %x, size: %x' % (func_ea, func_end_ea, func_size))
    output['rva'] = ea_to_rva(func_ea)
    output['start_ea'] = func_ea
    output['end_ea'] = func_end_ea

    # find switch
    head, switch = find_switch(func_ea)

    global main_jumptable
    main_jumptable = head

    if switch == None:
        log('failed to find switch in opcode handler')
        return
    
    # get switch cases
    res = idaapi.calc_switch_cases(head, switch)

    # get basic blocks
    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))

    output['cases'] = case_infos = []

    for idx, case in enumerate(res.cases):
        case_ea = res.targets[idx];
        rel_ea = case_ea - func_ea

        case_info = {
            'rva': ea_to_rva(case_ea),
            'start_ea': case_ea,
            'rel_ea': rel_ea
        }

        block = find_block(case_ea, blocks)
        
        if block != None:
            case_info['end_ea'] = block.endEA;
            case_info['size'] = block.endEA - case_ea

            # -1 to make it actually clickable in the output window and it goes to the right place
            #log('end: %x, size: %x' % ((block.endEA - 1), case_info['size']), 2)

        else:
            log('failed to get block for %x' % case_ea)
            continue

        case_info['opcodes'] = [int(oc) for oc in case]

        case_infos.append(case_info)

    log('got %d case info objs, switch blocks: %d' % (len(case_infos), len(res.cases)))

    for k, v in enumerate(case_infos):
        process_case(v, k)

    set_clipboard_json(output)

class xiv_opcode_parser_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL

    wanted_name = 'Find FFXIV Opcodes'
    wanted_hotkey = ''

    comment = 'Does magic and shit'
    help = 'no'
 
    def init(self):
        return idaapi.PLUGIN_OK
 
    def run(self, arg):
        run()
 
    def term(self):
        pass
 
def PLUGIN_ENTRY():
    return xiv_opcode_parser_t()