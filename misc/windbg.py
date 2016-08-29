from __future__ import print_function

import datetime
import functools
import threading
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer

import idaapi
import idautils
import idc

import socket
import subprocess
from contextlib import closing

# Wait for any processing to get done
idaapi.autoWait()

# Save the database so nothing gets lost.
idc.SaveBase(idc.GetIdbPath() + '.' + datetime.datetime.now().isoformat())

xmlrpclib.Marshaller.dispatch[type(0L)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)
xmlrpclib.Marshaller.dispatch[type(0)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

port       = 50000
orig_LineA = idc.LineA

def LineA(*a,**kw):
    v = orig_LineA(*a,**kw)
    if v and v.startswith('\x01\x04; '):
        v = v[4:]
    return v

idc.LineA = LineA

mutex = threading.Condition()

def wrap(f):
    def wrapper(*a, **kw):
        try:
            rv = []
            def work(): rv.append(f(*a,**kw))
            with mutex:
                flags = idaapi.MFF_WRITE
                if f == idc.SetColor:
                    flags |= idaapi.MFF_NOWAIT
                    rv.append(None)
                idaapi.execute_sync(work, flags)
            print(f, a, kw)
            print(f(*a, **kw))
            print(rv)
            if len(rv) > 0:
                return rv[0]
            return ''
        except:
            import traceback
            traceback.print_exc()
            raise
    return wrapper

def register_module(module):
    for name, function in module.__dict__.items():
        if hasattr(function, '__call__'):
            server.register_function(wrap(function), '{}.{}'.format(module.__name__, name))

def is_port_open(port):
    # TODO: make this not so hacky
    netstat = subprocess.check_output(['netstat', '-ant'])
    for line in netstat.split('\n'):
        if 'LISTENING' in line and str(port) in line:
            return False

    return True

for p in range(port, port+1000):
    if is_port_open(p):
        break
else:
    print("No ports open.. dahell?")
    import sys; sys.exit(0)

port = p

server = SimpleXMLRPCServer(('0.0.0.0', p), logRequests=True, allow_none=True)

register_module(idc)
register_module(idautils)
register_module(idaapi)

import database
import function
import custom
import instruction
import tools
register_module(database)
register_module(function)
register_module(custom)
register_module(instruction)
register_module(tools)
server.register_introspection_functions()

thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()

print("Your port: {}".format(p))
