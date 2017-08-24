# some general python modules
import sys,os,__builtin__
import imp,fnmatch,ctypes,types
import idaapi

library = ctypes.WinDLL if os.name == 'nt' else ctypes.CDLL

# grab ida's user directory and remove from path since we use meta_path to locate api modules
root = idaapi.get_user_idadir()
sys.path.remove(root)

class internal_api(object):
    """Meta-path base-class for an api that's based on files within a directory"""
    os,imp,fnmatch = os,imp,fnmatch
    def __init__(self, directory, **attributes):
        self.path = self.os.path.realpath(directory)
        [setattr(self, k, v) for k,v in attributes.iteritems()]

    ### Api operations
    def load_api(self, path):
        path,filename = self.os.path.split(path)
        name,_ = self.os.path.splitext(filename)
        return self.imp.find_module(name,[ path ])

    def iterate_api(self, include='*.py', exclude=None):
        result = []
        for filename in self.fnmatch.filter(self.os.listdir(self.path), include):
            if exclude and self.fnmatch.fnmatch(filename, exclude):
                continue

            path = self.os.path.join(self.path, filename)
            _,ext = self.os.path.splitext(filename)

            left,right = (None,None) if include == '*' else (include.index('*'),len(include)-include.rindex('*'))
            modulename = filename[left:-right+1]
            yield modulename,path
        return

    def new_api(self, modulename, path):
        file,path,description = self.load_api(path)
        try:
            return self.imp.load_module(modulename, file, path, description)
        finally: file.close()

    ### Module operations
    def new_module(self, fullname, doc=None):
        res = self.imp.new_module(fullname)
        res.__doc__ = doc or ''
        return res

    def find_module(self, fullname, path=None):
        raise NotImplementedError

    def load_module(self, fullname):
        raise NotImplementedError

class internal_path(internal_api):
    sys = sys
    def __init__(self, path, **attrs):
        super(internal_path,self).__init__(path)
        attrs.setdefault('include','*.py')
        self.attrs = attrs
        self.cache = dict(self.iterate_api(**attrs))

    def find_module(self, fullname, path=None):
        return self if path is None and fullname in self.cache else None

    def load_module(self, fullname):
        self.cache = dict(self.iterate_api(**self.attrs))
        res = self.sys.modules[fullname] = self.new_api(fullname, self.cache[fullname])
        return res

class internal_submodule(internal_api):
    sys = sys
    def __init__(self, __name__, path, **attrs):
        super(internal_submodule,self).__init__(path)
        attrs.setdefault('include','*.py')
        self.__name__ = __name__
        self.attrs = attrs

    def find_module(self, fullname, path=None):
        return self if path is None and fullname == self.__name__ else None

    def filter_module(self, filename):
        return self.fnmatch.fnmatch(filename, self.attrs['include']) and ('exclude' in self.attrs and not self.fnmatch.fnmatch(filename, self.attrs['exclude']))
    def fetch_module(self, name):
        cache = dict(self.iterate_api(**self.attrs))
        return self.new_api(name, cache[name])

    class module(types.ModuleType):
        def __init__(self, path, **attrs):
            self.__path__ = path
            self.__filter__ = attrs['filter']
            self.__module__ = attrs['getmodule']

            # FIXME: create a get-descriptor for each sub-module that will try to
            #        load the module continuously until it's finally successful

        @property
        def __dict__(self):
            files = filter(self.__filter__, os.listdir(self.__path__))
            return { n : self.__module__(n) for n in files }

        def __getattr__(self, name):
            import os
            res = self.__module__(n)
            #res = self.new_api(name, os.path.join(self.__path__, name))
            setattr(self, name, res)
            return res
            #raise NotImplementedError("Unable to fetch module {:s} on-demand".format(name))

    def load_module(self, fullname):
        # FIXME: make module a lazy-loaded object for fetching module-code on-demand
        module = self.sys.modules.setdefault(fullname, self.new_module(fullname))

        cache = dict(self.iterate_api(**self.attrs))
        module.__doc__ = '\n'.join('{:s} -- {:s}'.format(name, path) for name,path in sorted(cache.iteritems()))

        for name,path in cache.iteritems():
            try:
                res = self.new_api(name, path)
            except:
                __import__('logging').warn('{:s} : Unable to import module {:s} from {!r}'.format(self.__name__, name, path), exc_info=True)
            else:
                setattr(module, name, res)
            continue
        return module

class internal_object(object):
    def __init__(self, name, object):
        self.name,self.object = name,object
    def find_module(self, fullname, path=None):
        return self if path is None and fullname == self.name else None
    def load_module(self, fullname):
        assert fullname == self.name
        return self.object

class plugin_module(object):
    def __init__(self, path, **attrs):
        # FIXME: go through all files in plugin/ and call PLUGIN_ENTRY() on each module
        #        this should return an idaapi.plugin_t.

        # idaapi.plugin_t will contain an init, run, and term method.
        # also, are some attributes to process:
        # 'wanted_name' which is for idc.
        # 'wanted_hotkey', which should be mapped to a keypress.
        # 'comment' self-explanatory
        # 'help' self-explanatory

        # hotkey can be done by:
        # idaapi.CompileLine('static myname() { RunPythonStateMent("CallSomePython()") }')
        # idc.AddHotKey(module.wanted_hotkey, "myname")

        # idaapi.require
        pass

# ida's native api
if sys.platform == 'darwin':
    sys.meta_path.append( internal_object('ida',library(idaapi.idadir('libida.dylib'))) )
elif sys.platform in 'linux2':
    sys.meta_path.append( internal_object('ida',library('libida.so')) )
elif sys.platform == 'win32':
    sys.meta_path.append( internal_object('ida',library(idaapi.idadir('ida.wll'))) )
else:
    raise NotImplementedError

# private api
sys.meta_path.append( internal_submodule('internal', os.path.join(root,'base'), include='_*.py') )

# public api
sys.meta_path.append( internal_path(os.path.join(root,'base'), exclude='_*.py') )
sys.meta_path.append( internal_path(os.path.join(root,'misc')) )

# user and application api's
for n in ('custom','app'):
    sys.meta_path.append( internal_submodule(n, os.path.join(root,n)) )

# temporarily root namespace
__root__ = imp.load_source('__root__', os.path.join(root,'__root__.py'))

# empty out idapython's namespace
map(globals().pop, filter(lambda(_):not _.startswith('_'),globals().copy().keys()))

# re-populate with a default namespace and empty out our variable
globals().update(__root__.__dict__)
globals().pop('__root__')

# try and execute our user's idapythonrc.py
try:
    try:
        # execute user's .pythonrc and .idapythonrc in one go
        if __import__('user').home:
            execfile(__import__('os').path.join(__import__('user').home, '.idapythonrc.py'))

    except ImportError:
        # otherwise try to figure it out without tainting the namespace
        if __import__('os').getenv('HOME'):
            execfile(__import__('os').path.join(__import__('os').getenv('HOME'), '.idapythonrc.py'))
        elif __import__('os').getenv('USERPROFILE'):
            execfile(__import__('os').path.join(__import__('os').getenv('USERPROFILE'), '.idapythonrc.py'))
        else:
            raise OSError('Unable to figure out home directory')
        pass

except IOError:
    __import__('logging').warn('No idapythonrc.py file found in home directory')

except Exception, e:
    print('warning: Unexpected exception {!r} raised'.format(e))
    __import__('traceback').print_exc()

# find the frame that fucks with our sys.modules, and save it for later
__builtin__._ = __import__('sys')._getframe()
while __builtin__._.f_code.co_name != 'IDAPython_ExecScript':
    __builtin__._ = __builtin__._.f_back

# inject our current sys.modules state into IDAPython_ExecScript's state if it's the broken version
if 'basemodules' in __builtin__._.f_locals:
    __builtin__._.f_locals['basemodules'].update(__import__('sys').modules)
del(__builtin__._)
