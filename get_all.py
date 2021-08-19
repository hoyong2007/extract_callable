from util import *
import json
import os
import sys
from pprint import pprint
import r2pipe
from subprocess import check_output
import time


callable_functions = dict()
syscall_file = ''
System_map_file = ''

syscalls = ''
system_map = ''
version = ''

def get_pipe(vmlinux_file, version):
    plist = check_output(['r2', '-p']).strip().split('\n')
    project = 'project_%s' % (version.replace('.','_'))
    if project in plist and False:
        print('Open %s' % project)
        print(vmlinux_file)
        r = r2pipe.open('vmlinux', ['-p', project])
    else:
        print('Open new')
        r = r2pipe.open('vmlinux')
        r.cmd('aaa')
    return r

def init(kpath):
    # parse basic information
    syscall_file = os.path.join(kpath, 'arch/x86/entry/syscalls/syscall_64.tbl')
    System_map_file = os.path.join(kpath, 'System.map')
    vmlinux_file = os.path.join(kpath, 'vmlinux')

    system_map = get_system_map(System_map_file)
    syscall_list = get_syscall_list(syscall_file, system_map)
    version = kpath.split('linux-')[1].replace('/','')

    # analyze with radare and get handle
    cwd = os.getcwd()
    os.chdir(kpath)
    r = get_pipe(vmlinux_file, version)
    os.chdir(cwd)

    # make result directoy
    logdir = os.path.join(cwd, 'result-%s' % version)
    if not os.path.isdir(logdir):
        os.mkdir(logdir)

    return r, version, system_map, syscall_list

def get_ref(data, function, address):
    imports = []
    for d in data:
        f = d['name'].lower().replace('dbg.','')
        f = f.replace('sym.','')
        f = f.replace('obj.','')
        f = f.replace('loc.','')
        
        if f == address.replace('0x',''): # find with address
            imports = d['imports']
            break
        if f == function:   # find with function name
            imports = d['imports']
            break

    return imports

depth_function = ''
callable_functions = dict()
def extract_callable_function(data, function, address, depth):
    global depth_function, callable_functions

    depth_function += '  ' * depth
    depth_function += '%s\n' % func

    refs = get_ref(data, function, address)
    for name in refs:
        if 'unk.' in name:  # skip unknown
            continue

        f = name.lower().replace('dbg.','')
        f = f.replace('sym.','')
        f = f.replace('obj.','')
        f = f.replace('loc.','')
        if 'fcn.' in f:
            addr = '0x' + f.replace('fcn.','')
        else:
            addr = name2addr(f)

        if addr == '' or is_func(addr) == False:
            continue
        
        func = addr2name(addr)
        if func not in callable_functions:
            callable_functions[func] = addr
            extract_callable_function(data, func, addr, depth+1)

    return callable_functions


# Analyze all functions with radare2 and extract basic block info for each function
def step1(result_path, r, system_map):
    print("start analyzing each functions...")
    sysmap_sorted = sorted(system_map.items(), key=lambda sys:int(sys[1]['addr'],16), reverse=False)
    total_bb = ''
    end_addr = '0'
    for sys in sysmap_sorted:
        name = sys[0]
        addr = sys[1]['addr']
        if is_func(addr) == False:
            continue
        if int(addr,16) < int(end_addr, 16):    # skip if addr is already analyzed
            continue

        r.cmd('s %s' % addr)
        r.cmd('af')
        bb_info = get_basicblock(r, {'name':name, 'addr':addr})
        if '0xffffff' not in bb_info:   # Cannot find function
            continue
        total_bb += bb_info
        #print bb_info
        end_addr = '0'
        for bb in bb_info.strip().split('\n')[1:]:
            bb = bb.split(':')
            start = bb[0]
            bb = bb[1].split(' ')
            end = bb[0]
            size = bb[1]
            if '0xffffff' not in end:
                continue
            if start == end_addr or end_addr == '0':
                end_addr = end
            elif start[:-2] == end_addr[:-2]:
                end_addr = end
                print 'not same but in range'
    
    r.cmd('agCj > %s/out.json' % result_path)
    print('extract out.json successs')

    with open('%s/total_bb.lst' % result_path, 'w') as f:
        f.write(total_bb)


def step2(result_path, data, system_map, syscall_list):
    global depth_function, callable_functions

    for func in syscall_list:
        addr = name2addr(func)
        if addr != None:
            callable_function[func] = addr
            extract_callable_function(data, func, addr, 0)

    extracted_callable_with_name = ''
    for f in callable_functions.items():
        extracted_callable_with_name += '%s\n' % str(f)
    with open('%s/callable_with_name.lst' % result_path, 'w') as f:
        f.write(extracted_callable_with_name)
    with open('%s/callable_with_depth.lst' % result_path, 'w') as f:
        f.write(depth_function)


def step3(result_path, r, system_map):
    cfs = get_callable_functions('%s/callable_with_name.lst' % result_path)
    total_bb = get_totalbb('%s/total_bb.lst' % result_path)
    
    result = ''
    for info in cfs:
        result += get_basicblock(r, info)
    with open('%s/callable_bb.lst' % result_path, 'w') as f:
        f.write(result)


def main():
    r, version, system_map, syscall_list = init(sys.argv[1])
    print(version, r)

    cwd = os.getcwd()
    result_path = os.path.join(cwd, 'result-%s' % version)
    totalbb_file = os.path.join(result_path, 'total_bb.lst')
    json_file = os.path.join(result_path, 'out.json')
    syscall_file = os.path.join(result_path, 'target_syscalls.lst')

    step1(result_path, r, system_map)
    data = get_json(json_file)
    step2(result_path, data, system_map, syscall_list)
    step3(result_path, r, system_map)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python get_all.py <kernel_path>')
        print('   ex) python get_all.py ../kernel/linux-4.4/')
        exit(0)

    main()

