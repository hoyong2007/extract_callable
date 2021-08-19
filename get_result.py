from util import *
import os
import sys
import json
import bisect


def get_total_func(system_map):
    result = list()

    for symbol in system_map:
        if is_func(system_map[symbol]):
            result.append({'name':symbol, 'addr':system_map[symbol]['addr']})

    return result


# get system call related functions rate against total functions in linux
def step1(system_map, callable_func, data):
    flist = list()
    for d in data:
        f = d['name'].replace('dbg.','')
        f = f.replace('sym.','')
        f = f.replace('obj.','')
        f = f.replace('loc.','')

        if f in system_map:
        	if is_func(system_map[f]) and system_map[f]['addr'] not in flist:
                flist.append(system_map[f]['addr'])
        elif 'fcn.' in f:	# for kernel without symbols
            addr = f.replace('fcn.','')
            if is_func(addr) and addr not in flist:
                flist.append(addr)
    total_cnt = len(flist)
    print('Total functions : ', total_cnt)

    callable_cnt = 0
    for func in callable_func:
        if is_func(func):
            callable_cnt += 1
            
    print('System Call related functions: ', callable_cnt)
    print('Rate: %.3f%%' % (100*callable_cnt/float(total_cnt)))


# get system call related basic blocks rate against total basic blocks in linux functions
def step2(system_map, callable_func, callable_bb, total_bb):
    total_cnt = 0
    for symbol in system_map:
        if symbol in total_bb and is_func(system_map[symbol]):
            total_cnt += len(total_bb[symbol]['bb'])
    print('Total Basic Blocks: ', total_cnt)

    callablebb_cnt = 0
    for func in callable_func:
        if is_func(func):
            callablebb_cnt += len(callable_bb[func['name']]['bb'])
    print('Callable Basic Blocks: ', callablebb_cnt)
    print('Rate: %.3f%%' % (100*callablebb_cnt/float(total_cnt)))

    return callablebb_cnt


def lower_bound(addr_list, target):
    left, right = 0, len(addr_list) - 1
    while left < right:
        mid = (left + right) // 2
        if addr_list[mid]['addr'] < target:
            left = mid + 1
        else:
            right = mid
    return right


def check_range(bb_info, target):
    if bb_info['addr'] <= target and target <= (bb_info['addr'] + bb_info['size']):
        return True
    return False

# check the number of executed basic blocks
def evaluate_log(addr_list, logfile):
    check = [0] * len(addr_list)
    
    with open(logfile, 'r') as f:
        data = f.read().strip().split('\n')
        #print 'Total hit:', len(data)
        for hit in data:
            hitaddr = int(hit, 16)
            idx = lower_bound(addr_list, hitaddr)
            if check_range(addr_list[idx], hitaddr):
                check[idx] = 1
            elif idx > 0 and check_range(addr_list[idx-1], hitaddr):
                check[idx] = 1

    return sum(check)

# check the number of executed related functions
def evaluate_log2(addr_list, logfile):
    checked = set()

    with open(logfile, 'r') as f:
        data = f.read().strip().split('\n')
        #print 'Total hit:', len(data)
        for hit in data:
            hitaddr = int(hit, 16)
            idx = lower_bound(addr_list, hitaddr)

            if check_range(addr_list[idx], hitaddr):
                checked.add(addr_list[idx]['name'])

            elif idx > 0 and check_range(addr_list[idx-1], hitaddr):
                checked.add(addr_list[idx]['name'])

    return len(checked)

def evaluate_log3(addr_list, logfile):
    checked = set()

    with open(logfile, 'r') as f:
        data = f.read().strip().split('\n')
        #print 'Total hit:', len(data)
        for hit in data:
            hitaddr = int(hit, 16)
            idx = lower_bound(addr_list, hitaddr)

            if check_range(addr_list[idx], hitaddr):
                checked.add(addr_list[idx]['name'])

            elif idx > 0 and check_range(addr_list[idx-1], hitaddr):
                checked.add(addr_list[idx]['name'])

    return len(checked)


def step3(logdir, system_map, callable_func, callable_bb, callable_cnt, total_func, total_bb):
    addr_list = list()
    func_list = list()
    sorted_bb = list()

    for func in callable_func:
        if is_func(func):
            for bb in callable_bb[func['name']]['bb']:
                addr_list.append({'addr':bb['start'], 'name':func['name'], 'size':bb['size']})
    
    for func in total_func:
        if is_func(func['addr']) and func['name'] in total_bb:
            for bb in total_bb[func['name']]['bb']:
                func_list.append({'addr':bb['start'], 'name':func['name'], 'size':bb['size']})


    addr_list.sort(key=lambda block: block['addr'])
    func_list.sort(key=lambda block: block['addr'])
    
    logfile_list = [log for log in os.listdir(logdir) if '.log' in log]
    logfile_list.sort(key=lambda log: int(log.split('.')[0]))
    #logfile_list = [logdir]

    for logfile_name in logfile_list:
	    logfile = os.path.join(logdir, logfile_name)
	    tmp_str = dir_str #+ '/' + str(i) + '.log'
	    print(logfile)
	    total_exec_count= sum(1 for line in open(logfile, 'r'))
	    print("Executed Basic Blocks:", total_exec_count)

	    total_exec_function = evaluate_log3(func_list, logfile)
	    print("Executed Functions:", total_exec_function)

	    related_exec_count = evaluate_log(addr_list, logfile)
	    print("Executed Related Basic Blocks:", related_exec_count)

	    related_exec_function = evaluate_log2(addr_list, logfile)
	    print("Executed Related Functions:", related_exec_function)



def main():
    cwd = os.getcwd()
    kernel_path = os.path.join(cwd, sys.argv[1])
    log_path = os.path.join(cwd, sys.argv[2])
    version = kernel_path.split('linux-')[1].replace('/','')
    cwd = os.getcwd()
    result_path = os.path.join(cwd, 'result-%s' % version)

    System_map_file = os.path.join(kernel_path, 'System.map')
    callable_funcfile = os.path.join(result_path, 'callable_with_name.lst')
    callable_basicfile = os.path.join(result_path, 'callable_bb.lst')
    total_basicfile = os.path.join(result_path, 'total_bb.lst')
    json_file = os.path.join(result_path, 'out.json')

    system_map = get_system_map(System_map_file)
    total_func = get_total_func(system_map)
    callable_func = get_callable_functions(callable_funcfile)
    callable_bb = get_basicblock_from_file(callable_basicfile)
    total_bb = get_basicblock_from_file(total_basicfile)
    data = get_json(json_file)

    os.chdir(result_path)
    step1(system_map, callable_func, data)
    callable_cnt = step2(system_map, callable_func, callable_bb, total_bb)
    step3(log_path, system_map, callable_func, callable_bb, callable_cnt, total_func, total_bb)
    
    print(len(callable_func), len(callable_bb))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python get_result.py <kernel_path> <log_path>')
        print('   ex) python get_result.py ../kernel/linux-4.14 ~/access/logs/time_4.14')
    else:
        main()
