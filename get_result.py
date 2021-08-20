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


def evaluate_log(logfile, callable_list, total_list):
    check_related_bb = [0] * len(callable_list)
    check_total_function = set()
    check_related_function = set()
    check_total_bb = 0

    with open(logfile, 'r') as f:
        data = f.read().strip().split('\n')

    for hit in data:
        hitaddr = int(hit, 16)
        idx_C = lower_bound(callable_list, hitaddr)
        idx_T = lower_bound(total_list, hitaddr)

        # check the number of related bb & function
        if check_range(callable_list[idx_C], hitaddr):
            check_related_bb[idx_C] = 1
            check_related_function.add(callable_list[idx_C]['name'])
        elif idx_C > 0 and check_range(callable_list[idx_C - 1], hitaddr):
            check_related_bb[idx_C - 1] = 1
            check_related_function.add(callable_list[idx_C - 1]['name'])

        # check the number of executed bb & function
        check_total_bb += 1
        if check_range(total_list[idx_T], hitaddr):
            check_total_function.add(total_list[idx_T]['name'])
        elif idx_T > 0 and check_range(total_list[idx_T - 1], hitaddr):
            check_total_function.add(total_list[idx_T - 1]['name'])

    return sum(check_related_bb), check_total_bb, len(check_related_function), len(check_total_function)


def step3(logdir, callable_func, callable_bb, total_func, total_bb):
    callable_list = list()
    total_list = list()
    cnt = dict()

    for func in callable_func:
        if is_func(func):
            for bb in callable_bb[func['name']]['bb']:
                callable_list.append({'addr':bb['start'], 'name':func['name'], 'size':bb['size']})
    
    for func in total_func:
        if is_func(func['addr']) and func['name'] in total_bb:
            for bb in total_bb[func['name']]['bb']:
                total_list.append({'addr':bb['start'], 'name':func['name'], 'size':bb['size']})

    callable_list.sort(key=lambda block: block['addr'])
    total_list.sort(key=lambda block: block['addr'])
  
    logfile_list = list()
    if os.path.isdir(logdir):
        logfile_list = [log for log in os.listdir(logdir) if '.log' in log]
        logfile_list.sort(key=lambda log: int(log.split('.')[0]))
    elif os.path.isfile(logdir):
        logfile_list = [logdir]

    if len(logfile_list) == 0:
        print("\nerror: %s is not log file/directory" % logdir)
        return

    for logfile_name in logfile_list:
        logfile = os.path.join(logdir, logfile_name)
        ret = evaluate_log(logfile, callable_list, total_list)
        
        cnt['executed_related_bb'] = ret[0]
        cnt['executed_bb']   = ret[1]
        cnt['executed_related_function'] = ret[2]
        cnt['executed_function']   = ret[3]

        print('\n - %s' % '/'.join(logfile.split('/')[-2:]))
        print("Executed Basic Blocks: %d" % cnt['executed_bb'])
        print("Executed Related Basic Blocks: %d" % cnt['executed_related_bb'])
        print("Executed Functions: %d" % cnt['executed_function'])
        print("Executed Related Functions: %d" % cnt['executed_related_function'])


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
    step2(system_map, callable_func, callable_bb, total_bb)
    step3(log_path, callable_func, callable_bb, total_func, total_bb)
    

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python get_result.py <kernel_path> <log_path(dir/file)>')
        print('   ex) python get_result.py ../kernel/linux-4.14 ~/access/logs/time_4.14/')
        print('   ex) python get_result.py ../kernel/linux-4.14 ~/access/logs/time_4.14/32.log')
    else:
        main()
