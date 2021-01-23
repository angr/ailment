
from .tagged_object import TaggedObject


class Expression(TaggedObject):
    """
    The base class of all AIL expressions.
    """

    __slots__ = ('depth', )

    def __init__(self, idx, depth, **kwargs):
        super().__init__(idx, **kwargs)
        self.depth = depth

    def __repr__(self):
        raise NotImplementedError()

    def has_atom(self, atom, identity=True):
        if identity:
            return self is atom
        else:
            return self.likes(atom)

    def likes(self, atom):  # pylint:disable=unused-argument,no-self-use
        return False

    def replace(self, old_expr, new_expr):
        if self is old_expr:
            r = True
            replaced = new_expr
        elif not isinstance(self, Atom):
            r, replaced = self.replace(old_expr, new_expr)
        else:
            r, replaced = False, self

        return r, replaced

    def __add__(self, other):
        return BinaryOp(None, 'Add', [ self, other ], False)

    def __sub__(self, other):
        return BinaryOp(None, 'Sub', [ self, other ], False)


class Atom(Expression):

    __slots__ = ('variable', 'variable_offset', )

    def __init__(self, idx, variable, variable_offset=0, **kwargs):
        super().__init__(idx, 0, **kwargs)
        self.variable = variable
        self.variable_offset = variable_offset

    def __repr__(self):
        return "Atom (%d)" % self.idx

    def copy(self):  # pylint:disable=no-self-use
        return NotImplementedError()


class Const(Atom):

    __slots__ = ('value', 'bits', )

    def __init__(self, idx, variable, value, bits, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.value = value
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "%#x<%d>" % (self.value, self.bits)

    def __eq__(self, other):
        return type(self) is type(other) and \
            self.value == other.value and \
            self.bits == other.bits

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash((self.value, self.bits))

    @property
    def sign_bit(self):
        return self.value >> (self.bits - 1)

    def copy(self) -> 'Const':
        return Const(self.idx, self.variable, self.value, self.bits, **self.tags)


class Tmp(Atom):

    __slots__ = ('tmp_idx', 'bits', )

    def __init__(self, idx, variable, tmp_idx, bits, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.tmp_idx = tmp_idx
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "t%d" % self.tmp_idx

    def __eq__(self, other):
        return type(self) is type(other) and \
            self.tmp_idx == other.tmp_idx and \
            self.bits == other.bits

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash(('tmp', self.tmp_idx, self.bits))

    def copy(self) -> 'Tmp':
        return Tmp(self.idx, self.variable, self.tmp_idx, self.bits, **self.tags)


class Register(Atom):

    __slots__ = ('reg_offset', 'bits', )

    def __init__(self, idx, variable, reg_offset, bits, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.reg_offset = reg_offset
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def likes(self, atom):
        return type(self) is type(atom) and \
                self.reg_offset == atom.reg_offset and \
                self.bits == atom.bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        if hasattr(self, 'reg_name'):
            return "%s<%d>" % (self.reg_name, self.bits // 8)
        if self.variable is None:
            return "reg_%d<%d>" % (self.reg_offset, self.bits // 8)
        else:
            return "%s" % str(self.variable.name)

    def __eq__(self, other):
        return self.likes(other) and self.idx == other.idx

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash(('reg', self.reg_offset, self.bits, self.idx))

    def copy(self) -> 'Register':
        return Register(self.idx, self.variable, self.reg_offset, self.bits, **self.tags)


class Op(Expression):

    __slots__ = ('op', )

    def __init__(self, idx, depth, op, **kwargs):
        super().__init__(idx, depth, **kwargs)
        self.op = op

    @property
    def verbose_op(self):
        return self.op


class UnaryOp(Op):

    __slots__ = ('operand', 'bits', 'variable', 'variable_offset', )

    def __init__(self, idx, op, operand, variable=None, variable_offset=None, **kwargs):
        super().__init__(idx, (operand.depth if isinstance(operand, Expression) else 0) + 1, op, **kwargs)

        self.operand = operand
        self.bits = operand.bits
        self.variable = variable
        self.variable_offset = variable_offset

    def __str__(self):
        return "(%s %s)" % (self.op, str(self.operand))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return type(other) is UnaryOp and \
               self.op == other.op and \
               self.operand == other.operand and \
               self.bits == other.bits

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash((self.op, self.operand, self.bits))

    def replace(self, old_expr, new_expr):
        r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, UnaryOp(self.idx, self.op, replaced_operand, **self.tags)
        else:
            return False, self

    @property
    def operands(self):
        return [ self.operand ]

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> 'UnaryOp':
        return UnaryOp(self.idx, self.op, self.operand, variable=self.variable, variable_offset=self.variable_offset,
                       **self.tags)

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True
        return self.operand.has_atom(atom, identity=identity)


class Convert(UnaryOp):

    __slots__ = ('from_bits', 'to_bits', 'is_signed', )

    def __init__(self, idx, from_bits, to_bits, is_signed, operand, **kwargs):
        super().__init__(idx, 'Convert', operand, **kwargs)

        self.from_bits = from_bits
        self.to_bits = to_bits
        # override the size
        self.bits = to_bits
        self.is_signed = is_signed

    def __str__(self):
        return "Conv(%d->%d, %s)" % (self.from_bits, self.to_bits, self.operand)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return type(other) is Convert and \
               self.operand == other.operand and \
               self.from_bits == other.from_bits and \
               self.to_bits == other.to_bits and \
               self.bits == other.bits and \
               self.is_signed == other.is_signed

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash((self.operand, self.from_bits, self.to_bits, self.bits, self.is_signed))

    def replace(self, old_expr, new_expr):
        if self.operand.likes(old_expr):
            r = True
            replaced_operand = new_expr
        else:
            r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, Convert(self.idx, self.from_bits, self.to_bits, self.is_signed, replaced_operand, **self.tags)
        else:
            return False, self

    def copy(self) -> 'Convert':
        return Convert(self.idx, self.from_bits, self.to_bits, self.is_signed, self.operand, **self.tags)


class BinaryOp(Op):

    __slots__ = ('operands', 'bits', 'signed', 'variable', 'variable_offset', )

    OPSTR_MAP = {
        'Add': '+',
        'Sub': '-',
        'Mul': '*',
        'Div': '/',
        'Xor': '^',
        'And': '&',
        'LogicalAnd': '&&',
        'Or': '|',
        'LogicalOr': '||',
        'Shl': '<<',
        'Shr': '>>',
        'Sar': '>>a',
        'CmpEQ': '==',
        'CmpNE': '!=',
        'CmpLT': '<',
        'CmpLE': '<=',
        'CmpGT': '>',
        'CmpGE': '>=',
        'CmpLTs': '<s',
        'CmpLEs': '<=s',
        'CmpGTs': '>s',
        'CmpGEs': '>=s',
        'Concat': 'CONCAT',
    }

    def __init__(self, idx, op, operands, signed, variable=None, variable_offset=None, **kwargs):
        depth = max(
            operands[0].depth if isinstance(operands[0], Expression) else 0,
            operands[1].depth if isinstance(operands[1], Expression) else 0,
        ) + 1
        super().__init__(idx, depth, op, **kwargs)

        assert len(operands) == 2
        self.operands = operands
        self.bits = operands[0].bits if type(operands[0]) is not int else operands[1].bits
        self.signed = signed
        self.variable = variable
        self.variable_offset = variable_offset

        # TODO: sanity check of operands' sizes for some ops
        # assert self.bits == operands[1].bits

    def __str__(self):
        op_str = self.OPSTR_MAP.get(self.verbose_op, self.verbose_op)
        return "(%s %s %s)" % (str(self.operands[0]), op_str, str(self.operands[1]))

    def __repr__(self):
        return "%s(%s, %s)" % (self.verbose_op, self.operands[0], self.operands[1])

    def __eq__(self, other):
        return type(other) is BinaryOp and \
               self.operands == other.operands and \
               self.op == other.op and \
               self.bits == other.bits and \
               self.signed == other.signed

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash((self.op, tuple(self.operands), self.bits, self.signed))

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True

        for op in self.operands:
            if identity and op == atom:
                return True
            if not identity and op.likes(atom):
                return True
            if op.has_atom(atom, identity=identity):
                return True
        return False

    def replace(self, old_expr, new_expr):
        if self.operands[0] == old_expr:
            r0 = True
            replaced_operand_0 = new_expr
        else:
            r0, replaced_operand_0 = self.operands[0].replace(old_expr, new_expr)

        if self.operands[1] == old_expr:
            r1 = True
            replaced_operand_1 = new_expr
        else:
            r1, replaced_operand_1 = self.operands[1].replace(old_expr, new_expr)

        if r0 or r1:
            return True, BinaryOp(self.idx, self.op, [ replaced_operand_0, replaced_operand_1 ], self.signed,
                                  **self.tags)
        else:
            return False, self

    @property
    def verbose_op(self):
        op = self.op
        if self.signed:
            op += "s"
        return op

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> 'BinaryOp':
        return BinaryOp(self.idx, self.op, self.operands[::], self.signed, variable=self.variable,
                        variable_offset=self.variable_offset, **self.tags)


class Load(Expression):

    __slots__ = ('addr', 'size', 'endness', 'variable', 'variable_offset', 'guard', 'alt', )

    def __init__(self, idx, addr, size, endness, variable=None, variable_offset=None, guard=None, alt=None, **kwargs):
        depth = max(addr.depth, size.depth if isinstance(size, Expression) else 0) + 1
        super().__init__(idx, depth, **kwargs)

        self.addr = addr
        self.size = size
        self.endness = endness
        self.guard = guard
        self.alt = alt
        self.variable = variable
        self.variable_offset = variable_offset

    @property
    def bits(self):
        return self.size * 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "Load(addr=%s, size=%d, endness=%s)" % (self.addr, self.size, self.endness)

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True

        if type(self.addr) is int:
            return False
        return self.addr.has_atom(atom, identity=identity)

    def replace(self, old_expr, new_expr):
        r, replaced_addr = self.addr.replace(old_expr, new_expr)

        if r:
            return True, Load(self.idx, replaced_addr, self.size, self.endness, **self.tags)
        else:
            return False, self

    def __eq__(self, other):
        return type(other) is Load and \
               self.addr == other.addr and \
               self.size == other.size and \
               self.endness == other.endness and \
               self.guard == other.guard and \
               self.alt == other.alt

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash(('Load', self.addr, self.size, self.endness))

    def copy(self) -> 'Load':
        return Load(self.idx, self.addr, self.size, self.endness, variable=self.variable,
                    variable_offset=self.variable_offset, guard=self.guard, alt=self.alt, **self.tags)


class ITE(Expression):

    __slots__ = ('cond', 'iffalse', 'iftrue', 'bits', )

    def __init__(self, idx, cond, iffalse, iftrue, **kwargs):
        depth = max(cond.depth if isinstance(cond, Expression) else 0,
                    iffalse.depth if isinstance(iffalse, Expression) else 0,
                    iftrue.depth if isinstance(iftrue, Expression) else 0
                    ) + 1
        super().__init__(idx, depth, **kwargs)

        self.cond = cond
        self.iffalse = iffalse
        self.iftrue = iftrue
        self.bits = iftrue.bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "((%s) ? (%s) : (%s))" % (self.cond, self.iftrue, self.iffalse)

    def _hash_core(self):
        return hash((ITE, self.cond, self.iffalse, self.iftrue, self.bits))

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True

        return self.cond.has_atom(atom, identity=identity) or \
               self.iftrue.has_atom(atom, identity=identity) or \
               self.iffalse.has_atom(atom, identity=identity)

    def replace(self, old_expr, new_expr):
        cond_replaced, new_cond = self.cond.replace(old_expr, new_expr)
        iffalse_replaced, new_iffalse = self.iffalse.replace(old_expr, new_expr)
        iftrue_replaced, new_iftrue = self.iftrue.replace(old_expr, new_expr)
        replaced = cond_replaced or iftrue_replaced or iffalse_replaced

        if replaced:
            return True, ITE(self.idx, new_cond, new_iffalse, new_iftrue, **self.tags)
        else:
            return False, self

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> 'ITE':
        return ITE(self.idx, self.cond, self.iffalse, self.iftrue, **self.tags)


class DirtyExpression(Expression):

    __slots__ = ('dirty_expr', )

    def __init__(self, idx, dirty_expr, **kwargs):
        super().__init__(idx, 1, **kwargs)
        self.dirty_expr = dirty_expr

    def replace(self, old_expr, new_expr):
        return False, self

    def __eq__(self, other):
        return type(other) is DirtyExpression and other.dirty_expr == self.dirty_expr

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash((DirtyExpression, self.dirty_expr))

    def __repr__(self):
        return "DirtyExpression (%s)" % type(self.dirty_expr)

    def __str__(self):
        return "[D] %s" % str(self.dirty_expr)

    def copy(self) -> 'DirtyExpression':
        return DirtyExpression(self.idx, self.dirty_expr, **self.tags)


#
# Special (Dummy) expressions
#


class BasePointerOffset(Expression):

    __slots__ = ('bits', 'base', 'offset', 'variable', 'variable_offset', )

    def __init__(self, idx, bits, base, offset, variable=None, variable_offset=None, **kwargs):
        super().__init__(idx, (offset.depth if isinstance(offset, Expression) else 0) + 1, **kwargs)
        self.bits = bits
        self.base = base
        self.offset = offset
        self.variable = variable
        self.variable_offset = variable_offset

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        if self.offset is None:
            return "BaseOffset(%s)" % self.base
        if isinstance(self.offset, int):
            return "BaseOffset(%s, %d)" % (self.base, self.offset)
        return "BaseOffset(%s, %s)" % (self.base, self.offset)

    def __str__(self):
        if self.offset is None:
            return str(self.base)
        if isinstance(self.offset, int):
            return "%s%+d" % (self.base, self.offset)
        return "%s+%s" % (self.base, self.offset)

    def __eq__(self, other):
        return type(other) is type(self) and \
               self.bits == other.bits and \
               self.base == other.base and \
               self.offset == other.offset

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return hash((self.bits, self.base, self.offset))

    def replace(self, old_expr, new_expr):
        if isinstance(self.base, Expression):
            base_replaced, new_base = self.base.replace(old_expr, new_expr)
        else:
            base_replaced, new_base = False, self.base
        if isinstance(self.offset, Expression):
            offset_replaced, new_offset = self.offset.replace(old_expr, new_expr)
        else:
            offset_replaced, new_offset = False, self.offset

        if base_replaced or offset_replaced:
            return True, BasePointerOffset(self.idx, self.bits, new_base, new_offset, **self.tags)
        return False, self

    def copy(self) -> 'BasePointerOffset':
        return BasePointerOffset(self.idx, self.bits, self.base, self.offset, **self.tags)


class StackBaseOffset(BasePointerOffset):

    __slots__ = ()

    def __init__(self, idx, bits, offset, **kwargs):
        # stack base offset is always signed
        if offset >= (1 << (bits - 1)):
            offset -= 1 << bits
        super().__init__(idx, bits, 'stack_base', offset, **kwargs)

    def copy(self) -> 'StackBaseOffset':
        return StackBaseOffset(self.idx, self.bits, self.offset, **self.tags)
