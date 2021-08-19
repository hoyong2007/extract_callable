import json
import os
import sys
from pprint import pprint
import r2pipe
from subprocess import check_output
import time

system_map = None

def get_json(json_file):
    with open(json_file) as f:  
        data = json.load(f)
    return data

def addr2name(addr):
    global system_map
    for sys in system_map:
        if system_map[sys]['addr'] == addr:
            return sys
    return ''

def name2addr(name):
    global system_map
    if name in system_map:
        return system_map[name]['addr']
    return ''


def is_func(func):
    global system_map
    if type(func) == str or type(func) == unicode:
        addr = int(func,  16)
    elif type(func) == dict:
        addr = int(func['addr'],16)
    else:
        addr = func

    stext = int(system_map['_stext']['addr'], 16)
    etext = int(system_map['_etext']['addr'], 16)
    if stext <= addr and addr <= etext:
        return True

    return False

# {'name': {'addr', 'code'}}
def get_system_map(System_map_file):
    global system_map
    with open(System_map_file, 'r') as f:
        data = f.read().strip()

    result = dict()
    for line in data.split('\n'):
        line = line.split()
        if len(line) != 3:
            continue
        addr = '0x' + line[0].strip()   # 0xffff~
        code = line[1].strip()          # t/T/d ...
        name = line[2].strip().lower()  # name of functions/symbols, only lowercase

        # for inline functions, add postfix  ex) func_1
        if name in result and 'sys_' not in name:
            idx = 1
            tmp = name
            while tmp in result:
                tmp = name + '_%d'%idx
                idx += 1
            name = tmp
                
        result[name] = {'addr':addr, 'code':code}
    system_map = result
    return result

# return list of syscalls which exist in system_map
def get_syscall_list(syscall_file, system_map):
    with open(syscall_file, 'r') as f:
        data = f.read().strip()

    result = list() 
    for line in data.split('\n'):
        if line.strip() == '':
            continue

        line = line.split('\t')
        if line[0] and line[0][0] == '#': # comment start with '#'
            continue

        sys_func = line[-1].strip()
        if sys_func in system_map.keys() and sys_func not in result:   # original
            result.append(sys_func)

        sys_func = sys_func.replace('__x64_sys_','sys_')
        sys_func = sys_func.replace('__x32_sys_','sys_')
        if sys_func in system_map.keys() and sys_func not in result:   # sys_func
            result.append(sys_func)

        tmp = 'k' + sys_func
        if tmp in system_map.keys() and tmp not in result:   # ksys_func
            result.append(tmp)

        tmp = '__x64_' + sys_func
        if tmp in system_map.keys() and tmp not in result:   # __x64_sys_func
            result.append(tmp)

        tmp = '__x32_' + sys_func
        if tmp in system_map.keys() and tmp not in result:   # __x32_sys_func
            result.append(tmp)

    return result

# [{'name', 'addr'}, {'name', 'addr'}, ...]
def get_callable_functions(callable_file):
    with open(callable_file, 'r') as f:
        data = f.read().strip().split('\n')

    result = list()
    for line in data:
        if line == '':
            continue

        tmp = eval(line)
        try:
            name = tmp[0]
            addr = tmp[1]
            if addr == 0 and 'fcn.' in name:
                addr = name.replace('fcn.','')
            
            result.append({'name':name, 'addr':addr})
        except:
            continue
    return result


def get_basicblock(r, info):
    #print(info['addr'])
    r.cmd('s %s' % info['addr'])
    raw = r.cmd('afb')

    bb_info = 'Function: %s\n' % info['name']
    if 'Cannot find function' in raw or raw.strip() == '':
        bb_info += '%s\n' % raw
        return bb_info

    for line in raw.strip().split('\n'):
        tmp = line.split()
        start = tmp[0]
        end = tmp[1]
        size = tmp[3]
        bb_info += '%s:%s %s\n' % (start, end, size)
    return bb_info


# {'name' : {'addr', 'bb':[{'start','end','size'}, ...]}}
def get_basicblock_from_file(bb_file):
    with open(bb_file) as f:
        data = f.read().strip().split('\n')

    readbb = dict()
    tbb = list()
    addr = -1
    name = data[0].split()[1]
    for line in data[1:]:
        if line.strip() == '':
            continue
        if 'Function: ' in line:    # function start
            readbb[name] = {'addr':addr, 'bb':tbb}
            name = line.split()[1]
            tbb = list()
            addr = -1
        else:   # bb info "start:end size"
            line = line.split()
            size = int(line[1])
            start = int(line[0].split(':')[0], 16)
            end = int(line[0].split(':')[1], 16)
            if addr == -1:
                addr = '0x'+line[0].split(':')[0]
            tbb.append({'start':start, 'end':end, 'size':size})

    readbb[name] = {'addr':addr, 'bb':tbb} # for last function

    return readbb
