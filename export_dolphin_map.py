import idc
import ida_kernwin

address = idc.get_next_func(0)
map_path = ida_kernwin.ask_file(1, "*.map", "Dolphin map file")
map_file = open(map_path, "w")
map_file.write(".text section layout\n")
while address != 4294967295: # 4294967295 = FFFFFFFF i.e. -1
    name = idc.get_func_name(address)
    demangled_name = idc.demangle_name(name, idc.get_inf_attr(INF_LONG_DN))
    if (demangled_name and len(demangled_name) > 1):
        name = demangled_name
    if (name and len(name) > 1):
        map_file.write("%08x %08x %08x 0 %s\n" % (address, idc.get_func_attr(address, FUNCATTR_END) - address, address, name))
    address = idc.get_next_func(address)
map_file.write("\n.data section layout\n")
map_file.close()