import itertools,operator,functools
from string import Template
import database as db,function as fn,instruction as ins, structure as struc
import idaapi
import logging
import os
import copy
from collections import namedtuple

func = fn

def windbgescape(result):
    result = result.replace("\\", "\\\\")
    return result

def eaToLabel(ea):
    try: res = '{:s}{{+{:x}}}'.format(fn.name(ea), db.offset(ea))
    except: res = '+{:x}'.format(db.offset(ea))
    return '{:s}!{:s}'.format(db.module(), res)

def eaToReference(ea):
    return '{:s}+{:x}'.format(db.module(),db.offset(ea))

def dump_breaks(func=None, tagname='break', stdout=True):
    if func is None:
        for func,_ in db.selectcontents(tagname):
            dump_breaks(func, tagname=tagname)
        return
    Escape = lambda s: s.replace('"', '\\"')

    entry,exit = fn.top(func),fn.bottom(func)
    funcname = fn.name(func)

    #[(entry,{tagname:'.printf "Entering {:s} %x,%x\\n",poi(@esp),@esp'.format(funcname)})], [(x,{tagname:'.printf "Exiting {:s} %x,%x\\n",poi(@esp),@esp'.format(funcname)}) for x in exit], 
    select = itertools.chain(fn.select(func, And=(tagname,), Or=('',)))

    res = {}
    for ea,t in select:
        h = res.setdefault(ea,{})
        for k in t.keys():
            if k == tagname:
                h.setdefault(k,[]).extend(t[k].split(';'))
            else:
                assert k not in h
                h[k] = t[k]
        continue

    output = []
    for ea,t in res.iteritems():
        ofs = db.offset(ea)

        commands = []
        label = Template('.printf "$label -- $note\\n"' if t.has_key('') else '.printf "$label\\n"')
        commands.append(label.safe_substitute(label=eaToLabel(ea), note=t.get('','')))
        commands.extend(t.get(tagname,['g']))
        commands = map(windbgescape,commands)

        curr_break = 'bp {:s} "{:s}"'.format(eaToReference(ea), Escape(';'.join(commands)))
        output.append(curr_break)
        if stdout:
            print(curr_break)

    return '\n' + '\n'.join(output) + '\n'

def write_breaks(func=None, tagname='break', append=False):
    breaks = dump_breaks(func=func, tagname=tagname, stdout=False)
    filename = os.path.join('F:\\', 'bps')
    open_mode = 'a' if append else 'wb'
    with open(filename, open_mode) as f:
        f.write(breaks)

    print("Writing breaks to {}".format(filename))

def dump_labels(func, statement="g"):
    Escape = lambda s: s.replace('"', '\\"')
    for ea,t in fn.select(func, 'name'):
        print 'bp {:s} ".printf \\"label {:s}:{:s}\\\\n\\";{:s}"'.format(eaToReference(ea), fn.name(func), Escape(t['name']), Escape(statement))
    return
        
def dump(func):
    dump_labels(func)
    dump_breaks(func)

def search(func, *tags):
    print '\n'.join(map(db.disasm,fn.select(func, Or=tags)))

def dump_breaks(func=None, tagname='break', stdout=True):
    if func is None:
        for func,_ in db.selectcontents(tagname):
            dump_breaks(func, tagname=tagname)
        return
    Escape = lambda s: s.replace('"', '\\"')

    entry,exit = fn.top(func),fn.bottom(func)
    funcname = fn.name(func)

    #[(entry,{tagname:'.printf "Entering {:s} %x,%x\\n",poi(@esp),@esp'.format(funcname)})], [(x,{tagname:'.printf "Exiting {:s} %x,%x\\n",poi(@esp),@esp'.format(funcname)}) for x in exit], 
    select = itertools.chain(fn.select(func, And=(tagname,), Or=('',)))

    res = {}
    for ea,t in select:
        h = res.setdefault(ea,{})
        for k in t.keys():
            if k == tagname:
                h.setdefault(k,[]).extend(t[k].split(';'))
            else:
                assert k not in h
                h[k] = t[k]
        continue

    output = []
    for ea,t in res.iteritems():
        ofs = db.offset(ea)

        commands = []
        label = Template('.printf "$label -- $note\\n"' if t.has_key('') else '.printf "$label\\n"')
        commands.append(label.safe_substitute(label=eaToLabel(ea), note=t.get('','')))
        commands.extend(t.get(tagname,['g']))
        commands = map(windbgescape,commands)

        breakpoint = 'bp {:s} "{:s}"'.format(eaToReference(ea), Escape(';'.join(commands)))
        if stdout:
            print(breakpoint)

        output.append(breakpoint)

    return '\n'.join(output)
    

def tag_marks():
    for ea, mark in db.marks():
        mark = mark.replace('[note]','')
        db.tag(ea, 'note', mark)

def rip_frame(st):
    '''Return a given function frame's stack variables'''
    return [((n.offset,n.name,n.type,n.comment) for n in st.members if all(not n.name.startswith(s) for s in (' ','var_', 'arg_')))]

def apply_frame(st, lst):
    '''Apply a given function' frame's stack variables'''
    for o,n,t,c in lst:
        m = st.by_offset(o) # possibly try/except
        if any(not n.startswith(s) for s in (' ','var_','arg_')):
            print "Renamed {:s}.{:s} to {:s}.{:s}".format(st.name, m.name, st.name, n)
        m.name,m.type,m.comment = n,t,c
    return

def rip_stackframes():
    '''Return all function frame's stack variables in a dict of lists'''
    return { ea : rip_frame(func.frame(ea)) for ea in db.functions() }

def apply_stackframes(res):
    '''Apply all function frame's stack variables from a dict of lists'''
    for ea, lst in res.iteritems():
        fr = func.frame(ea)
        apply_frame(fr, lst)
    return

def write_breaks(func=None, tagname='break', append=False):
    breaks = dump_breaks(func=func, tagname=tagname, stdout=False)
    filename = os.path.join('F:\\', 'bps')
    open_mode = 'a' if append else 'wb'
    with open(filename, open_mode) as f:
        f.write(breaks)

    print("Writing breaks to {}".format(filename))

def get_bb_id(graph, ea):
    for block in graph:
        if block.startEA <= ea and block.endEA > ea:
            return block.id

def color_block(ea=None, color=0x55ff7f):
    """http://reverseengineering.stackexchange.com/questions/10662/change-block-node-color-with-idapython
    and WanderingGlitch for the tip of refresh_idaview_anyway()"""

    func_top = fn.top()

    f = idaapi.get_func(ea)
    g = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    bb_id = get_bb_id(g, ea)

    p = idaapi.node_info_t()
    p.bg_color = color

    idaapi.set_node_info2(func_top, bb_id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
    idaapi.refresh_idaview_anyway()

def dump_trace(here, color=0x55ff7f):
    """Dump breakpoints for current function to trace to see basic blocks in function
    The trace dumps a file to F://trace.out.py which should be able to be imported into
    IDA to color the blocks 
    """
    filename = os.path.join('F:\\', 'trace')
    trace = set()

    try:
        with open(filename, 'r') as f:
            curr_trace = f.read().split('\n')

        # Keep trace that is currently written
        for t in curr_trace:
            trace.add(t)
    except IOError:
        pass


    print("Here: {}, color: {}".format(hex(here), hex(color)))
    for block in fn.blocks(here):
        begin, end = block
        command = 'bp {} ".printf \\"custom.cory.color_block({}, {})\\\\n\\"; g;"'.format(eaToReference(begin), hex(begin), hex(color))
        trace.add(command)

    with open(filename, 'w') as f:
        for t in trace:
            f.write(t + '\n')
        f.write('.logopen E:\\trace.out.py\n')

    print("Writing trace breakpoints to {}".format(filename))

def search_dyn_calls(addr, curr_addr_list=None, parents=None):
    dyn_call = namedtuple('dyn_call', ['call', 'parents'])
    hex = '{:x}'.format

    # print(hex(addr), curr_addr_list)
    if curr_addr_list == None:
        curr_addr_list = [addr]

    if parents == None:
        parents = []

    calls = []

    #print("Addr: {}".format(addr))
    for ea in fn.iterate(addr):
        if not ins.isCall(ea):
            continue

        call = ins.op_value(ea, 0)

        # Don't cycle ourselves
        if call == addr:
            # print("Ignoring recursive loop on function: {}".format(hex(addr)))
            continue

        # Don't call functions we are currently looking into
        if call in curr_addr_list:
            continue

        """
        .text:3F6E66AD 0B4                 call    ds:memmove
        Python>x = ins.op_value(h(), 0)
        Python>print(x.base)
        None
        .text:3F6E6208 008                 call    dword ptr [eax]
        Python>x.base
        <instruction.register.eax(0,dt_dword) 'eax' 0:+32>
        """
        # we want non int/long for calls
        if isinstance(call, (int, long)) and not ins.op_type(ea, 0) in ('phrase'):
            # Only now call the function once
            curr_addr_list.append(call)
            new_parents = copy.deepcopy(parents)
            new_parents.append(ea)
            calls.extend(search_dyn_call(call, curr_addr_list=curr_addr_list, parents=new_parents))
        elif isinstance(call, ins.intelop.OffsetBaseIndexScale) and call.base == None:
            # Ignore 'call ds:memmove' or 'call ds:atoi'
            # print("OffsetBase", call.offset, hex(ea)[2:-1], db.disasm(ea), parents)
            pass
        else:
            calls.append(dyn_call(ea, parents))

    return calls
"""Aliases"""
search_dyn_call = search_dyn_calls


def _search_func(addr, func, curr_addr_list=None):
    if curr_addr_list == None:
        curr_addr_list = [addr]

    for ea in fn.iterate(addr):

        func(ea)

        if not ins.isCall(ea):
            continue

        call = ins.op_value(ea, 0)

        # Don't cycle ourselves
        if call == addr:
            # print("Ignoring recursive loop on function: {}".format(hex(addr)))
            continue

        # Try to know if the call operand is a valid address
        # Bail if not.. 
        if not isinstance(call, (int, long)):
            continue
        """
        try:
            x = hex(call)
        except:
            continue
        """

        # Don't call functions we are currently looking into
        if call in curr_addr_list:
            continue

        # Only now ca
        curr_addr_list.append(call)
        _search_func(call, func, curr_addr_list=curr_addr_list)

def search_func(addr, funcname, curr_addr_list=None):
    """
    Given an address and function name, recursively look from the given address
    for calls to the given function name. Modifies the 'calls' function tag with
    the function name and True or False depending if the function contains the wanted
    function or not.
    """
    if curr_addr_list == None:
        curr_addr_list = [addr]

    print("Addr: {}".format(addr))
    curr_calls = fn.tag(addr).get('calls', {})
    for ea in fn.iterate(addr):
        if funcname in db.disasm(ea):
            curr_calls[funcname] = True
            fn.tag(addr, 'calls', curr_calls)
            return True

        if not ins.isCall(ea):
            continue

        call = ins.op_value(ea, 0)

        # Don't cycle ourselves
        if call == addr:
            print("Ignoring recursive loop on function: {}".format(hex(addr)))
            continue

        # Try to know if the call operand is a valid address
        # Bail if not.. 
        try:
            print(hex(call))
        except:
            continue

        # Check if this function has been analyzed already
        # and return the result
        # Cannot return False, because that will exit the loop and not 
        # continue to iterate over the rest of the instrutions in the function
        call_cache = fn.tag(call).get('calls', {})
        print("Call cache: {}".format(call_cache))
        if funcname in call_cache:
            if call_cache[funcname]:
                curr_calls[funcname] = call_cache[funcname]
                fn.tag(addr, 'calls', curr_calls)
                return True

        # Don't call functions we are currently looking into
        if call in curr_addr_list:
            continue

        # Only now ca
        curr_addr_list.append(call)
        search_func(call, funcname=funcname, curr_addr_list=curr_addr_list)

    curr_calls[funcname] = False
    fn.tag(addr, 'calls', curr_calls)
    return False

def search_malloc(addr, funcname='malloc', curr_addr_list=None):
    # print(hex(addr), curr_addr_list)
    if curr_addr_list == None:
        curr_addr_list = [addr]

    print("Addr: {}".format(addr))
    curr_calls = fn.tag(addr).get('calls', {})
    for ea in fn.iterate(addr):
        if not ins.isCall(ea):
            continue

        if ins.op_type(0) == 'reg':
            """
            Handle this case - malloc(100)
            mov ebp, ds:malloc
            push 100
            call ebp
            """

        if funcname in db.disasm(ea):
            # Push before malloc "should" be within 20 instructions
            """
            Handle this case - malloc(100)
            push 100
            mov eax, 10
            mov ebx, 20
            call malloc
            """
            search_addr = db.prev(ea)
            for _ in range(20):
                if ins.mnem(search_addr) == 'push':
                    break
                search_addr = db.prev(search_addr)

            print("FOUND PUSH FOR MALLOC: {}".format(hex(search_addr)))
            malloc_value = ins.op_value(search_addr, 0)
            if isinstance(malloc_value, (int, long)):
                curr_calls[funcname] = malloc_value
            else:
                curr_calls[funcname] = 'variable'

            fn.tag(addr, 'calls', curr_calls)
            return True

        call = ins.op_value(ea, 0)

        # Don't cycle ourselves
        if call == addr:
            print("Ignoring recursive loop on function: {}".format(hex(addr)))
            continue

        # Try to know if the call operand is a valid address
        # Bail if not.. 
        try:
            print(hex(call))
        except:
            continue

        # Check if this function has been analyzed already
        # and return the result
        # Cannot return False, because that will exit the loop and not 
        # continue to iterate over the rest of the instrutions in the function
        call_cache = fn.tag(call).get('calls', {})
        print("Call cache: {}".format(call_cache))
        if funcname in call_cache:
            if call_cache[funcname]:
                curr_calls[funcname] = call_cache[funcname]
                fn.tag(addr, 'calls', curr_calls)
                return True

        # Don't call functions we are currently looking into
        if call in curr_addr_list:
            continue

        # Only now ca
        curr_addr_list.append(call)
        search_malloc(call, funcname=funcname, curr_addr_list=curr_addr_list)

    curr_calls[funcname] = False
    fn.tag(addr, 'calls', curr_calls)
    return False

def apply_dyn_calls(dyn_calls, delete=False):
    hex = '{:x}'.format
    for dyn_call in dyn_calls:
        print(dyn_call)
        for i,p in enumerate(dyn_call.parents):
            print(i, hex(p))
            top = func.top(p)
            if 'dynamic_call' not in func.tag(top): fn.tag(top, 'dynamic_call', set())
            if delete:
                fn.tag(top,'dynamic_call', None)
                continue
            curr_tag = fn.tag(top, 'dynamic_call')
            print(type(curr_tag), hex(top))
            try:
                curr_tag.add(dyn_call.parents[i+1])
            except IndexError:
                curr_tag.add(dyn_call.call)
            fn.tag(top, 'dynamic_call', curr_tag)

        # Be sure to tag the actual function containing the dynamic call
        top = fn.top(dyn_call.call)
        if delete:
            if 'dynamic_call' in fn.tag(top):
                fn.tag(top, 'dynamic_call', None)
            if 'dynamic_call' in fn.tag(dyn_call.call):
                fn.tag(dyn_call.call, 'dynamic_call', None)
            continue

        if 'dynamic_call' not in fn.tag(top): fn.tag(top, 'dynamic_call', set())
        curr_tag = fn.tag(top, 'dynamic_call')
        curr_tag.add(dyn_call.call)
        fn.tag(top, 'dynamic_call', curr_tag)
        db.tag(dyn_call.call, 'dynamic_call', 'here')

def mov_search(addr):
    def check(ea):
        if 'mov' not in db.disasm(ea) or 'offset' not in db.disasm(ea):
            return
        if ins.ops_type(ea) != ['phrase', 'immediate']:
            return
        if ins.op_value(ea, 0).offset != 0:
            return

        print(hex(ea), db.disasm(ea), ins.ops_type())

    _search_func(addr, func=check)
        

        
