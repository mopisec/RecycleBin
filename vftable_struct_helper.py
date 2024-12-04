# vftable_struct_helper.py
# IDAPython script that creates structure of vftable, and associates xref between its field and each virtual function of the class
# Author: Naoki Takayama
# License: The MIT License

import idautils
import idc

vftable_ea = idc.here()
step = 8

def get_vftable_functions(ea):
    global step

    r = []
        
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_dword(flags):
        step = 4
        
    is_first = True
    while is_first or idc.get_name(ea) == '':
        if step == 8:
            target = ida_bytes.get_qword(ea)
        elif step == 4:
            target = ida_bytes.get_dword(ea)
            
        # Check if target is address of function or not
        if ida_bytes.is_func(ida_bytes.get_flags(target)):
            r.append(target)
            
        ea += step
        is_first = False
        
    return r

class_name = demangle_name(get_name(vftable_ea), 0)[6:].split('::')[0]
struct_name = class_name + '_vftable'
vftable_list = get_vftable_functions(vftable_ea)
# print(vftable_list)

idc.add_struc(0, struct_name, 0)
struct_id = idc.get_struc_id(struct_name)
for i in range(len(vftable_list)):
    if step == 4:
        idc.add_struc_member(struct_id, ida_name.get_name(vftable_list[i]), i * 4, idaapi.FF_DWORD, -1, step)
    elif step == 8:
        idc.add_struc_member(struct_id, ida_name.get_name(vftable_list[i]), i * 8, idaapi.FF_QWORD, -1, 8)
    else:
        print('[-] Unknown step value')

_type = parse_decl(struct_name, 0)  
idc.apply_type(vftable_ea, _type, 0)
print(f'Created strucuture {struct_name} and applied it to {hex(vftable_ea)}')

cnt = 0
idx = 0

while(idx < len(vftable_list) * step):
    member_id = idc.get_member_id(struct_id, idx)
    member_name = idc.get_struc_name(member_id)

    if member_id == 0xffffffff:
        idx += 1
        continue
    
    _from = member_id
    to = vftable_list[cnt]
    r = ida_xref.add_dref(_from, to, ida_xref.XREF_USER)

    print(f'Added xref from {member_name} to {hex(to)}')

    idx = idx + step
    cnt += 1
