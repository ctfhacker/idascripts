import itertools,operator,functools
from string import Template
import database as db,function as fn,instruction as ins, structure as struc
import idaapi
import logging
import os

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
