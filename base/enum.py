'''
enum-context
generic tools for working with enumerations

Examples:
e = enum.create("example_enum")
e = enum.byName("example_enum")

print enum.name(e), enum.comment(e)
print enum.size(e), enum.mask(e)

for e in enum.iterate():
    print enum.keys(e),enum.values(e)
    print enum.repr(e)

enum.delete("example_enum")
'''

import __builtin__
import sys,six,math
import functools,itertools,operator
import logging,fnmatch,re
import internal
from internal import utils,interface as ui
import idaapi

# FIXME: complete this with more types similar to the 'structure' module.
# FIXME: normalize the documentation.

def count():
    '''Return the total number of enumerations in the database.'''
    return idaapi.get_enum_qty()

@utils.multicase(enum=six.integer_types)
def flags(enum):
    return idaapi.get_enum_flag(enum)
@utils.multicase(enum=six.integer_types, mask=six.integer_types)
def flags(enum, mask):
    return idaapi.get_enum_flag(enum) & mask

def by_name(name):
    '''Return an enum id with the specified ``name``.'''
    res = idaapi.get_enum(name)
    if res == idaapi.BADADDR:
        raise LookupError("{:s}.by_name({!r}) : Unable to locate enumeration.".format(__name__, name))
    return res
byName = utils.alias(by_name)

def by_index(index):
    '''Return an enum id at the specified ``index``.'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise LookupError("{:s}.by_index({:x}) : Unable to locate enumeration.".format(__name__, index))
    return res
byIndex = utils.alias(by_index)

@utils.multicase(index=six.integer_types)
def by(index):
    bits = int(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
    highbyte = 0xff << (bits-8)
    if index & highbyte == highbyte:
        return index
    return by_index(index)
@utils.multicase(name=basestring)
def by(name):
    return by_name(name)

def keys(id):
    '''Return the names of all of the elements of the enumeration ``id``.'''
    return [member.name(n) for n in member.iterate(id)]

def values(id):
    '''Return the values of all of the elements of the enumeration ``id``.'''
    return [member.value(n) for n in member.iterate(id)]

## creation/deletion
def new(name, flags=0):
    '''Create an enumeration with the specified ``name``.'''
    idx = count()
    res = idaapi.add_enum(idx, name, flags)
    if res == idaapi.BADADDR:
        raise ValueError("{:s}.create : Unable to create enumeration named {:s}".format(__name__, name))
    return res

@utils.multicase(id=six.integer_types)
def delete(id):
    return idaapi.del_enum(id)
@utils.multicase(name=basestring)
def delete(name):
    '''Delete the enumeration with the specified ``name``.'''
    eid = by_name(name)
    return delete(eid)
create,remove = utils.alias(new),utils.alias(delete)

## setting enum options
@utils.multicase()
def name(enum):
    '''Return the name of the enumeration identified by ``enum``.'''
    eid = by(enum)
    return idaapi.get_enum_name(eid)
@utils.multicase(name=basestring)
def name(enum, name):
    '''Rename the enumeration identified by ``enum`` to ``name``.'''
    eid = by(enum)
    return idaapi.set_enum_name(eid, name)

@utils.multicase()
def comment(enum, **repeatable):
    """Return the comment for the enumeration identified by ``enum``.
    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    eid = by(enum)
    return idaapi.get_enum_cmt(eid, repeatable.get('repeatable', True))
@utils.multicase(comment=basestring)
def comment(enum, comment, **repeatable):
    """Set the comment for the enumeration identified by ``enum`` to ``comment``.
    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    eid = by(enum)
    return idaapi.set_enum_cmt(eid, comment, repeatable.get('repeatable', True))

@utils.multicase()
def size(enum):
    '''Return the size of the enumeration identified by ``enum``.'''
    eid = by(enum)
    res = idaapi.get_enum_width(eid)
    return 2**(res-1) if res > 0 else 0
@utils.multicase(width=six.integer_types)
def size(enum, width):
    '''Set the size of the enumeration identified by ``enum`` to ``width``.'''
    eid = by(enum)
    res = int(math.log(width, 2))
    return idaapi.set_enum_width(eid, int(res)+1)

def mask(enum):
    '''Return the bitmask for the enumeration identified by ``enum``.'''
    eid = by(enum)
    res = min((size(eid), 4))    # FIXME: is uval_t/bmask_t a maximum of 32bits on ida64 too?
    if res > 0:
        return 2**(res*8)-1
    return sys.maxint*2+1

def members(enum):
    '''Return the name of each member from the enumeration identified by ``enum``.'''
    eid = by(enum)
    for n in member.iterate(eid):
        yield member.name(n)
    return

def repr(enum):
    '''Return a printable summary of the enumeration identified by ``enum``.'''
    eid = by(enum)
    w = size(eid)*2
    result = [(member.name(n),member.value(n),member.mask(n),member.comment(n)) for n in member.iterate(eid)]
    aligned = max((len(n) for n,_,_,_ in result))
    return "<type 'enum'> {:s}\n".format(name(eid)) + '\n'.join(('[{:d}] {:<{align}s} : {:#0{width}x} & {:#0{width}x}'.format(i, name, value, bmask, width=w+2, align=aligned)+((' # '+comment) if comment else '') for i,(name,value,bmask,comment) in enumerate(result)))

__matcher__ = utils.matcher()
__matcher__.attribute('index', idaapi.get_enum_idx)
__matcher__.boolean('regex', re.search, idaapi.get_enum_name)
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), idaapi.get_enum_name)
__matcher__.boolean('name', operator.eq, idaapi.get_enum_name)
__matcher__.attribute('id')
__matcher__.attribute('identifier')
__matcher__.predicate('pred')
__matcher__.predicate('predicate')

def __iterate__():
    '''Iterate through all enumeration ids defined in the database.'''
    for n in __builtin__.range(idaapi.get_enum_qty()):
        yield idaapi.getn_enum(n)
    return

def iterate(**type):
    '''Yield the id of each enumeration within the database.'''
    if not type: type = {'predicate':lambda n: True}
    res = __builtin__.list(__iterate__())
    for k,v in type.iteritems():
        res = __builtin__.list(__matcher__.match(k, v, res))
    for n in res: yield n

@utils.multicase(string=basestring)
def list(string):
    '''List any enumerations that match the glob in `string`.'''
    return list(like=string)
@utils.multicase()
def list(**type):
    """List all the enumerations within the database.

    Search type can be identified by providing a named argument.
    like = glob match
    regex = regular expression
    index = particular index
    identifier = particular id number
    pred = function predicate
    """
    res = __builtin__.list(iterate(**type))

    maxindex = max(__builtin__.map(idaapi.get_enum_idx, res))
    maxname = max(__builtin__.map(utils.compose(idaapi.get_enum_name, len), res))
    maxsize = max(__builtin__.map(size, res))
    cindex = math.ceil(math.log(maxindex or 1)/math.log(10))
    cmask = max(__builtin__.map(utils.compose(mask, math.log, functools.partial(operator.mul, 1.0/math.log(16)), math.ceil), res) or [database.config.bits()/4.0])

    for n in res:
        print('[{:{:d}d}] {:>{:d}s} & {:#<{:d}x} ({:d} members){:s}'.format(idaapi.get_enum_idx(n), int(cindex), idaapi.get_enum_name(n), maxname, mask(n), int(cmask), len(__builtin__.list(members(n))), ' // {:s}'.format(comment(n)) if comment(n) else ''))
    return

@utils.multicase(string=basestring)
def search(string):
    '''Search through all the enumerations using globbing.'''
    return search(like=string)
@utils.multicase()
def search(**type):
    """Search through all the enumerations within the database and return the first result.

    like = glob match
    regex = regular expression
    index = particular index
    identifier or id = internal id number
    """
    searchstring = ', '.join('{:s}={!r}'.format(k,v) for k,v in type.iteritems())

    res = __builtin__.list(iterate(**type))
    if len(res) > 1:
        map(logging.info, ('[{:d}] {:s} & {:#x} ({:d} members){:s}'.format(idaapi.get_enum_idx(n), idaapi.get_enum_name(n), mask(n), len(__builtin__.list(members(n))), ' // {:s}'.format(comment(n)) if comment(n) else '') for i,n in enumerate(res)))
        logging.warn('{:s}.search({:s}) : Found {:d} matching results, returning the first one.'.format(__name__, searchstring, len(res)))

    res = next(iter(res), None)
    if res is None:
        raise LookupError('{:s}.search({:s}) : Found 0 matching results.'.format(__name__, searchstring))
    return res

## members
class member(object):
    '''This class allows one to interact with the members of a defined enumeration.

    Examples:
        e = enum.byName('example_enumeration')
        print enum.repr(e)

        enum.member.rename(e, 'oldname', 'newname')

        n = enum.member.add(e, 'name', 0x1000)
        enum.member.remove(n)

        n = enum.member.byName(e, 'name')
        n = enum.member.byValue(e, 0x1000)

        enum.member.name(n, 'somename')
        enum.member.value(n, 0x100)
        enum.member.comment(n, 'This is an test value')

        for n in enum.member.iterate(e):
            print enum.member.name(n)
            print enum.member.value(n)
            print enum.member.comment(n)
    '''

    @classmethod
    def parent(cls, mid):
        '''Return the enumeration id that owns the member ``mid``.'''
        return idaapi.get_enum_member_enum(mid)

    ## lifetime
    @classmethod
    def add(cls, enum, name, value, **bitmask):
        """Add an enumeration member ``name`` with the specified ``value`` to the enumeration identified by ``enum``.
        If the int, ``bitmask``, is specified then used it as the bitmask for the enumeration.
        """
        eid = by(enum)
        bmask = bitmask.get('bitmask', -1&mask(eid))

        res = interface.tuplename(name) if isinstance(name, tuple) else name
        ok = idaapi.add_enum_member(eid, res, value, bmask)

        if ok in (idaapi.ENUM_MEMBER_ERROR_NAME, idaapi.ENUM_MEMBER_ERROR_VALUE, idaapi.ENUM_MEMBER_ERROR_ENUM, idaapi.ENUM_MEMBER_ERROR_MASK, idaapi.ENUM_MEMBER_ERROR_ILLV):
            raise ValueError("{:s}.add({:x}, {!r}, {:x}, bitmask={!r}) : Unable to add member to enumeration.".format('.'.join((__name__,cls.__name__)), eid, name, value, bitmask))
        return cls.by_value(eid, value)
    new = create = utils.alias(add, 'member')

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def remove(cls, mid):
        '''Remove the enumeration member with the given ``mid``.'''
        value = cls.value(mid)
        # XXX: is a serial of 0 valid?
        res = idaapi.del_enum_member(cls.parent(mid), value, 0, -1&cls.mask(mid))
        if not res:
            raise LookupError("{:s}.member._remove({:x}) : Unable to remove member from enumeration.".format(__name__, mid))
        return res
    @utils.multicase()
    @classmethod
    def remove(cls, enum, member):
        '''Remove the specified ``member`` of the enumeration ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.remove(mid)
    delete = destroy = utils.alias(remove, 'member')

    ## searching
    @classmethod
    def by_index(cls, enum, index):
        '''Return the member id for the member of the enumeration ``enum`` at the specified ``index``.'''
        eid = by(enum)
        try: return next(m for i,m in enumerate(cls.iterate(eid)) if i == index)
        except StopIteration: pass
        raise LookupError("{:s}.by_index({:x}, {:d}) : Unable to locate member by index.".format('.'.join((__name__,cls.__name__)), eid, index))

    @classmethod
    def by_identifer(cls, enum, mid):
        eid = by(enum)
        if cls.parent(mid) != eid:
            raise LookupError("{:s}.by_identifier({:x}, {:d}) : Unable to locate member by id.".format('.'.join((__name__,cls.__name__)), eid, index))
        return mid

    @classmethod
    def by_value(cls, enum, value):
        '''Return the member id for the member of the enumeration ``enum`` with the specified ``value``.'''
        eid = by(enum)
        bmask = -1&mask(eid)
        res,_ = idaapi.get_first_serial_enum_member(eid, value, bmask)
        if res == idaapi.BADADDR:
            raise LookupError("{:s}.by_value({:x}, {:d}) : Unable to locate member by value.".format('.'.join((__name__,cls.__name__)), eid, value))
        return res
    byValue = utils.alias(by_value, 'member')

    @classmethod
    def by_name(cls, enum, name):
        '''Return the member id for the member of the enumeration ``enum`` with the specified ``name``.'''
        eid = by(enum)
        for mid in cls.iterate(eid):
            if name == cls.name(mid):
                return mid
            continue
        return
    byName = utils.alias(by_name, 'member')

    @utils.multicase(n=six.integer_types)
    @classmethod
    def by(cls, enum, n):
        '''Return the member belonging to ``enum`` identified by it's index, or it's id.'''
        bits = int(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
        highbyte = 0xff << (bits-8)
        if n & highbyte == highbyte:
            return cls.by_identifier(enum, n)
        return cls.by_index(enum, n)
    @utils.multicase(member=basestring)
    @classmethod
    def by(cls, enum, member):
        '''Return the member with the given ``name`` belonging to ``enum``.'''
        return cls.by_name(enum, member)

    ## properties
    @utils.multicase(mid=six.integer_types)
    @classmethod
    def name(cls, mid):
        '''Return the name of the enumeration member ``mid``.'''
        return idaapi.get_enum_member_name(mid)
    @utils.multicase()
    @classmethod
    def name(cls, enum, member):
        '''Return the name of the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.name(mid)
    @utils.multicase(mid=six.integer_types, name=(basestring,tuple))
    @classmethod
    def name(cls, mid, name):
        '''Rename the enumeration member ``mid`` to ``name``.'''
        res = interface.tuplename(*name) if isinstance(name, tuple) else name
        return idaapi.set_enum_member_name(mid, res)
    @utils.multicase(name=basestring)
    @classmethod
    def name(cls, enum, member, name, *suffix):
        '''Rename the enumeration ``member`` of ``enum`` to ``name```.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        res = (name,) + suffix
        return cls.name(eid, interface.tuplename(*res))
    rename = utils.alias(name, 'member')

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def comment(cls, mid, **repeatable):
        """Return the comment for the enumeration member id ``mid``.
        If the bool ``repeatable`` is specified, then return the repeatable comment.
        """
        return idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True))
    @utils.multicase(name=basestring)
    @classmethod
    def comment(cls, enum, member, **repeatable):
        '''Return the comment for the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, name)
        return cls.comment(mid, **repeatable)
    @utils.multicase(mid=six.integer_types, comment=basestring)
    @classmethod
    def comment(cls, mid, comment, **repeatable):
        """Set the comment for the enumeration member id ``mid`` to ``comment``.
        If the bool ``repeatable`` is specified, then set the repeatable comment.
        """
        return idaapi.set_enum_member_cmt(mid, comment, kwds.get('repeatable', True))
    @utils.multicase(comment=basestring)
    @classmethod
    def comment(cls, enum, member, comment, **repeatable):
        '''Set the comment for the enumeration ``member`` belonging to ``enum`` to the string ``comment``.'''
        eid = by(enum)
        mid = cls.by(eid, name)
        return cls.comment(mid, comment, **repeatable)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def value(cls, mid):
        '''Return the value of the enumeration member ``mid``.'''
        return idaapi.get_enum_member_value(mid)
    @utils.multicase()
    @classmethod
    def value(cls, enum, member):
        '''Return the value of the specified ``member`` belonging to the enumeration ``enum``.'''
        eid = by(enum)
        mid = cls.by(member)
        return cls.value(mid)
    @utils.multicase(value=six.integer_types)
    @classmethod
    def value(cls, enum, member, value, **bitmask):
        """Set the ``value`` for the enumeration ``member`` belonging to ``enum``.
        If the integer ``bitmask`` is specified, then use it as a bitmask. Otherwise assume all bits are set.
        """
        eid = by(enum)
        mid = cls.by(enum, member)
        #bmask = bitmask.get('bitmask', -1 & mask(eid))
        bmask = bitmask.get('bitmask', -1 & cls.mask(mid))
        return idaapi.set_enum_member_value(mid, value, bmask)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def serial(cls, mid):
        '''Return the serial of the enumeration member ``mid``.'''
        return idaapi.get_enum_member_serial(mid)
    @utils.multicase()
    @classmethod
    def serial(cls, enum, member):
        '''Return the serial of the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.serial(mid)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def mask(cls, mid):
        '''Return the bitmask for the enumeration member ``mid``.'''
        return idaapi.get_enum_member_bmask(mid)
    @utils.multicase()
    @classmethod
    def mask(cls, enum, member):
        '''Return the bitmask for the enumeration ``member`` belonging to ``enum``.'''
        eid = by(enum)
        mid = cls.by(eid, member)
        return cls.mask(mid)

    # FIXME
    __member_matcher = utils.matcher()

    @classmethod
    def __iterate__(cls, eid):
        bmask = -1&mask(eid)
        res = idaapi.get_first_enum_member(eid, bmask)
        if res == idaapi.BADADDR: return
        yield res
        while res != idaapi.get_last_enum_member(eid, bmask):
            res = idaapi.get_next_enum_member(eid, res, bmask)
            yield res
        return

    @classmethod
    def iterate(cls, enum):
        '''Iterate through all the member ids associated with the enumeration ``enum``.'''
        eid = by(enum)
        bmask = -1&mask(eid)
        for v in cls.__iterate__(eid):
            res,_ = idaapi.get_first_serial_enum_member(eid, v, bmask)
            # XXX: what does get_next_serial_enum_member and the rest do?
            yield res
        return

    @classmethod
    def list(cls, enum):
        # FIXME: make this consistent with every other .list
        eid = by(enum)
        res = __builtin__.list(cls.iterate(eid))
        maxindex = max(__builtin__.map(utils.first, enumerate(res)) or [1])
        maxvalue = max(__builtin__.map(utils.compose(cls.value, '{:x}'.format, len), res) or [1])
        for i, mid in enumerate(res):
             print('[{:d}] {:>0{:d}x} {:s}'.format(i, cls.value(mid), maxvalue, cls.name(mid)))
        return
