# pylint:disable=isinstance-second-argument-not-valid-type,no-self-use,arguments-renamed
from __future__ import annotations
from typing import TYPE_CHECKING
from collections.abc import Sequence
from abc import ABC, abstractmethod
from typing_extensions import Self

try:
    import claripy
except ImportError:
    claripy = None

from .utils import stable_hash, is_none_or_likeable, is_none_or_matchable
from .tagged_object import TaggedObject
from .expression import Atom, Expression, DirtyExpression

if TYPE_CHECKING:
    from angr.calling_conventions import SimCC


class Statement(TaggedObject, ABC):
    """
    The base class of all AIL statements.
    """

    __slots__ = ()

    @abstractmethod
    def __repr__(self):
        raise NotImplementedError()

    @abstractmethod
    def __str__(self):
        raise NotImplementedError()

    @abstractmethod
    def replace(self, old_expr: Expression, new_expr: Expression) -> tuple[bool, Self]:
        raise NotImplementedError()

    def eq(self, expr0, expr1):  # pylint:disable=no-self-use
        if claripy is not None and (isinstance(expr0, claripy.ast.Base) or isinstance(expr1, claripy.ast.Base)):
            return expr0 is expr1
        return expr0 == expr1

    @abstractmethod
    def likes(self, other) -> bool:  # pylint:disable=unused-argument,no-self-use
        raise NotImplementedError()

    @abstractmethod
    def matches(self, other) -> bool:  # pylint:disable=unused-argument,no-self-use
        raise NotImplementedError()


class Assignment(Statement):
    """
    Assignment statement: expr_a = expr_b
    """

    __slots__ = (
        "dst",
        "src",
    )

    def __init__(self, idx: int | None, dst: Atom, src: Expression, **kwargs):
        super().__init__(idx, **kwargs)

        self.dst = dst
        self.src = src

    def __eq__(self, other):
        return type(other) is Assignment and self.idx == other.idx and self.dst == other.dst and self.src == other.src

    def likes(self, other):
        return type(other) is Assignment and self.dst.likes(other.dst) and self.src.likes(other.src)

    def matches(self, other):
        return type(other) is Assignment and self.dst.matches(other.dst) and self.src.matches(other.src)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Assignment, self.idx, self.dst, self.src))

    def __repr__(self):
        return f"Assignment ({self.dst}, {self.src})"

    def __str__(self):
        return f"{str(self.dst)} = {str(self.src)}"

    def replace(self, old_expr: Expression, new_expr: Expression):
        if self.dst == old_expr:
            r_dst = True
            assert isinstance(new_expr, Atom)
            replaced_dst = new_expr
        else:
            r_dst, replaced_dst = self.dst.replace(old_expr, new_expr)

        if self.src == old_expr:
            r_src = True
            replaced_src = new_expr
        else:
            r_src, replaced_src = self.src.replace(old_expr, new_expr)

        if r_dst or r_src:
            return True, Assignment(self.idx, replaced_dst, replaced_src, **self.tags)
        else:
            return False, self

    def copy(self) -> Assignment:
        return Assignment(self.idx, self.dst, self.src, **self.tags)


class Store(Statement):
    """
    Store statement: *addr = data
    """

    __slots__ = (
        "addr",
        "size",
        "data",
        "endness",
        "variable",
        "offset",
        "guard",
    )

    def __init__(
        self,
        idx: int | None,
        addr: Expression,
        data: Expression,
        size: int,
        endness: str,
        guard: Expression | None = None,
        variable=None,
        offset=None,
        **kwargs,
    ):
        super().__init__(idx, **kwargs)

        self.addr = addr
        self.data = data
        self.size = size
        self.endness = endness
        self.variable = variable
        self.guard = guard
        self.offset = offset  # variable_offset

    def __eq__(self, other):
        return (
            type(other) is Store
            and self.idx == other.idx
            and self.eq(self.addr, other.addr)
            and self.eq(self.data, other.data)
            and self.size == other.size
            and self.guard == other.guard
            and self.endness == other.endness
        )

    def likes(self, other):
        return (
            type(other) is Store
            and self.addr.likes(other.addr)
            and self.data.likes(other.data)
            and self.size == other.size
            and self.guard == other.guard
            and self.endness == other.endness
        )

    def matches(self, other):
        return (
            type(other) is Store
            and self.addr.matches(other.addr)
            and self.data.matches(other.data)
            and self.size == other.size
            and self.guard == other.guard
            and self.endness == other.endness
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Store, self.idx, self.addr, self.data, self.size, self.endness, self.guard))

    def __repr__(self):
        return "Store (%s, %s[%d])%s" % (
            self.addr,
            str(self.data),
            self.size,
            "" if self.guard is None else "[%s]" % self.guard,
        )

    def __str__(self):
        if self.variable is None:
            return "STORE(addr={}, data={}, size={}, endness={}, guard={})".format(
                self.addr, str(self.data), self.size, self.endness, self.guard
            )
        else:
            return "%s =%s %s<%d>%s" % (
                self.variable.name,
                "L" if self.endness == "Iend_LE" else "B",
                str(self.data),
                self.size,
                "" if self.guard is None else "[%s]" % self.guard,
            )

    def replace(self, old_expr, new_expr):
        if self.addr.likes(old_expr):
            r_addr = True
            replaced_addr = new_expr
        else:
            r_addr, replaced_addr = self.addr.replace(old_expr, new_expr)

        if isinstance(self.data, Expression):
            if self.data.likes(old_expr):
                r_data = True
                replaced_data = new_expr
            else:
                r_data, replaced_data = self.data.replace(old_expr, new_expr)
        else:
            r_data, replaced_data = False, self.data

        if self.guard is not None:
            r_guard, replaced_guard = self.guard.replace(old_expr, new_expr)
        else:
            r_guard, replaced_guard = False, None

        if r_addr or r_data or r_guard:
            return True, Store(
                self.idx,
                replaced_addr,
                replaced_data,
                self.size,
                self.endness,
                guard=replaced_guard,
                variable=self.variable,
                **self.tags,
            )
        else:
            return False, self

    def copy(self) -> Store:
        return Store(
            self.idx,
            self.addr,
            self.data,
            self.size,
            self.endness,
            guard=self.guard,
            variable=self.variable,
            offset=self.offset,
            **self.tags,
        )


class Jump(Statement):
    """
    Jump statement: goto target
    """

    __slots__ = (
        "target",
        "target_idx",
    )

    def __init__(self, idx: int | None, target: Expression, target_idx: int | None = None, **kwargs):
        super().__init__(idx, **kwargs)

        self.target = target
        self.target_idx = target_idx

    def __eq__(self, other):
        return type(other) is Jump and self.idx == other.idx and self.target == other.target

    def likes(self, other):
        return type(other) is Jump and is_none_or_likeable(self.target, other.target)

    def matches(self, other):
        return type(other) is Jump and is_none_or_matchable(self.target, other.target)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Jump, self.idx, self.target))

    def __repr__(self):
        if self.target_idx is not None:
            return f"Jump ({self.target}.{self.target_idx})"
        return "Jump (%s)" % self.target

    def __str__(self):
        if self.target_idx is not None:
            return f"Goto({self.target}.{self.target_idx})"
        return "Goto(%s)" % self.target

    @property
    def depth(self):
        return self.target.depth

    def replace(self, old_expr, new_expr):
        r, replaced_target = self.target.replace(old_expr, new_expr)

        if r:
            return True, Jump(self.idx, replaced_target, **self.tags)
        else:
            return False, self

    def copy(self):
        return Jump(
            self.idx,
            self.target,
            **self.tags,
        )


class ConditionalJump(Statement):
    """
    if (cond) {true_target} else {false_target}
    """

    __slots__ = (
        "condition",
        "true_target",
        "false_target",
        "true_target_idx",
        "false_target_idx",
    )

    def __init__(
        self,
        idx: int | None,
        condition: Expression,
        true_target: Expression | None,
        false_target: Expression | None,
        true_target_idx: int | None = None,
        false_target_idx: int | None = None,
        **kwargs,
    ):
        super().__init__(idx, **kwargs)

        self.condition = condition
        self.true_target = true_target
        self.false_target = false_target
        self.true_target_idx = true_target_idx
        self.false_target_idx = false_target_idx

    def __eq__(self, other):
        return (
            type(other) is ConditionalJump
            and self.idx == other.idx
            and self.condition == other.condition
            and self.true_target == other.true_target
            and self.false_target == other.false_target
            and self.true_target_idx == other.true_target_idx
            and self.false_target_idx == other.false_target_idx
        )

    def likes(self, other):
        return (
            type(other) is ConditionalJump
            and self.condition.likes(other.condition)
            and is_none_or_likeable(self.true_target, other.true_target)
            and is_none_or_likeable(self.false_target, other.false_target)
        )

    def matches(self, other):
        return (
            type(other) is ConditionalJump
            and self.condition.matches(other.condition)
            and is_none_or_matchable(self.true_target, other.true_target)
            and is_none_or_matchable(self.false_target, other.false_target)
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(
            (
                ConditionalJump,
                self.idx,
                self.condition,
                self.true_target,
                self.false_target,
                self.true_target_idx,
                self.false_target_idx,
            )
        )

    def __repr__(self):
        return "ConditionalJump (condition: {}, true: {}{}, false: {}{})".format(
            self.condition,
            self.true_target,
            "" if self.true_target_idx is None else f".{self.true_target_idx}",
            self.false_target,
            "" if self.false_target_idx is None else f".{self.false_target_idx}",
        )

    def __str__(self):
        return "if ({}) {{ Goto {}{} }} else {{ Goto {}{} }}".format(
            self.condition,
            self.true_target,
            "" if self.true_target_idx is None else f".{self.true_target_idx}",
            self.false_target,
            "" if self.false_target_idx is None else f".{self.false_target_idx}",
        )

    def replace(self, old_expr, new_expr):
        if self.condition == old_expr:
            r_cond = True
            replaced_cond = new_expr
        else:
            r_cond, replaced_cond = self.condition.replace(old_expr, new_expr)

        if self.true_target is not None:
            if self.true_target == old_expr:
                r_true = True
                replaced_true = new_expr
            else:
                r_true, replaced_true = self.true_target.replace(old_expr, new_expr)
        else:
            r_true, replaced_true = False, self.true_target

        if self.false_target is not None:
            if self.false_target == old_expr:
                r_false = True
                replaced_false = new_expr
            else:
                r_false, replaced_false = self.false_target.replace(old_expr, new_expr)
        else:
            r_false, replaced_false = False, self.false_target

        r = r_cond or r_true or r_false

        if r:
            return True, ConditionalJump(
                self.idx,
                replaced_cond,
                replaced_true,
                replaced_false,
                true_target_idx=self.true_target_idx,
                false_target_idx=self.false_target_idx,
                **self.tags,
            )
        else:
            return False, self

    def copy(self) -> ConditionalJump:
        return ConditionalJump(
            self.idx,
            self.condition,
            self.true_target,
            self.false_target,
            true_target_idx=self.true_target_idx,
            false_target_idx=self.false_target_idx,
            **self.tags,
        )


class Call(Expression, Statement):
    """
    Call is both an expression and a statement.

    When used as a statement, it will set ret_expr, fp_ret_expr, or both if both of them should hold return values.
    When used as an expression, both ret_expr and fp_ret_expr should be None (and should be ignored). The size of the
    call expression is stored in the bits attribute.
    """

    __slots__ = (
        "target",
        "calling_convention",
        "prototype",
        "args",
        "ret_expr",
        "fp_ret_expr",
    )

    def __init__(
        self,
        idx: int | None,
        target: Expression | str,
        calling_convention: SimCC | None = None,
        prototype=None,
        args: Sequence[Expression] | None = None,
        ret_expr: Expression | None = None,
        fp_ret_expr: Expression | None = None,
        bits: int | None = None,
        **kwargs,
    ):
        super().__init__(idx, target.depth + 1 if isinstance(target, Expression) else 1, **kwargs)

        self.target = target
        self.calling_convention = calling_convention
        self.prototype = prototype
        self.args = args
        self.ret_expr = ret_expr
        self.fp_ret_expr = fp_ret_expr
        if bits is not None:
            self.bits = bits
        elif ret_expr is not None:
            self.bits = ret_expr.bits
        elif fp_ret_expr is not None:
            self.bits = fp_ret_expr.bits
        else:
            self.bits = 0  # uhhhhhhhhhhhhhhhhhhh

    def likes(self, other):
        return (
            type(other) is Call
            and is_none_or_likeable(self.target, other.target)
            and self.calling_convention == other.calling_convention
            and self.prototype == other.prototype
            and is_none_or_likeable(self.args, other.args, is_list=True)
            and is_none_or_likeable(self.ret_expr, other.ret_expr)
            and is_none_or_likeable(self.fp_ret_expr, other.fp_ret_expr)
        )

    def matches(self, other):
        return (
            type(other) is Call
            and is_none_or_matchable(self.target, other.target)
            and self.calling_convention == other.calling_convention
            and self.prototype == other.prototype
            and is_none_or_matchable(self.args, other.args, is_list=True)
            and is_none_or_matchable(self.ret_expr, other.ret_expr)
            and is_none_or_matchable(self.fp_ret_expr, other.fp_ret_expr)
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Call, self.idx, self.target))

    def __repr__(self):
        return f"Call (target: {self.target}, prototype: {self.prototype}, args: {self.args})"

    def __str__(self):
        cc = "Unknown CC" if self.calling_convention is None else "%s" % self.calling_convention
        if self.args is None:
            if self.calling_convention is not None:
                s = (
                    ("%s" % cc)
                    if self.prototype is None
                    else f"{self.calling_convention}: {self.calling_convention.arg_locs(self.prototype)}"
                )
            else:
                s = ("%s" % cc) if self.prototype is None else repr(self.prototype)
        else:
            s = (f"{cc}: {self.args}") if self.prototype is None else f"{self.calling_convention}: {self.args}"

        if self.ret_expr is None:
            ret_s = "no-ret-value"
        else:
            ret_s = f"{self.ret_expr}"
        if self.fp_ret_expr is None:
            fp_ret_s = "no-fp-ret-value"
        else:
            fp_ret_s = f"{self.fp_ret_expr}"

        return f"Call({self.target}, {s}, ret: {ret_s}, fp_ret: {fp_ret_s})"

    @property
    def size(self):
        return self.bits // 8

    @property
    def verbose_op(self):
        return "call"

    @property
    def op(self):
        return "call"

    def replace(self, old_expr: Expression, new_expr: Expression):
        if isinstance(self.target, Expression):
            r0, replaced_target = self.target.replace(old_expr, new_expr)
        else:
            r0 = False
            replaced_target = self.target

        r = r0

        new_args = None
        if self.args:
            new_args = []
            for arg in self.args:
                if arg == old_expr:
                    r_arg = True
                    replaced_arg = new_expr
                else:
                    r_arg, replaced_arg = arg.replace(old_expr, new_expr)
                r |= r_arg
                new_args.append(replaced_arg)

        new_ret_expr = self.ret_expr
        new_bits = self.bits
        if self.ret_expr:
            if self.ret_expr == old_expr:
                r_ret = True
                replaced_ret = new_expr
            else:
                r_ret, replaced_ret = self.ret_expr.replace(old_expr, new_expr)
            r |= r_ret
            new_ret_expr = replaced_ret
            if replaced_ret is not None:
                new_bits = replaced_ret.bits

        new_fp_ret_expr = self.fp_ret_expr
        if self.fp_ret_expr:
            if self.fp_ret_expr == old_expr:
                r_ret = True
                replaced_fp_ret = new_expr
            else:
                r_ret, replaced_fp_ret = self.fp_ret_expr.replace(old_expr, new_expr)
            r |= r_ret
            new_fp_ret_expr = replaced_fp_ret

        if r:
            return True, Call(
                self.idx,
                replaced_target,
                calling_convention=self.calling_convention,
                prototype=self.prototype,
                args=new_args,
                ret_expr=new_ret_expr,
                fp_ret_expr=new_fp_ret_expr,
                bits=new_bits,
                **self.tags,
            )
        else:
            return False, self

    def copy(self):
        return Call(
            self.idx,
            self.target,
            calling_convention=self.calling_convention,
            prototype=self.prototype,
            args=self.args[::] if self.args is not None else None,
            ret_expr=self.ret_expr,
            fp_ret_expr=self.fp_ret_expr,
            bits=self.bits,
            **self.tags,
        )


class Return(Statement):
    """
    Return statement: (return expr_a), (return)
    """

    __slots__ = ("ret_exprs",)

    def __init__(self, idx: int | None, ret_exprs, **kwargs):
        super().__init__(idx, **kwargs)
        self.ret_exprs = ret_exprs if isinstance(ret_exprs, list) else list(ret_exprs)

    def __eq__(self, other):
        return type(other) is Return and self.idx == other.idx and self.ret_exprs == other.ret_exprs

    def likes(self, other):
        return type(other) is Return and is_none_or_likeable(self.ret_exprs, other.ret_exprs, is_list=True)

    def matches(self, other):
        return type(other) is Return and is_none_or_matchable(self.ret_exprs, other.ret_exprs, is_list=True)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Return, self.idx, tuple(self.ret_exprs)))

    def __repr__(self):
        return "Return to ({})".format(",".join(repr(x) for x in self.ret_exprs))

    def __str__(self):
        exprs = ",".join(str(ret_expr) for ret_expr in self.ret_exprs)
        if not exprs:
            return "return;"
        else:
            return "return %s;" % exprs

    def replace(self, old_expr, new_expr):
        new_ret_exprs = []
        replaced = False

        for expr in self.ret_exprs:
            if expr == old_expr:
                r_expr = True
                replaced_expr = new_expr
            else:
                r_expr, replaced_expr = expr.replace(old_expr, new_expr)
            if r_expr:
                replaced = True
                new_ret_exprs.append(replaced_expr)
            else:
                new_ret_exprs.append(old_expr)

        if replaced:
            return True, Return(
                self.idx,
                new_ret_exprs,
                **self.tags,
            )

        return False, self

    def copy(self):
        return Return(
            self.idx,
            self.ret_exprs[::],
            **self.tags,
        )


class DirtyStatement(Statement):
    """
    Wrapper around the original statement, which is usually not convertible (temporarily).
    """

    __slots__ = ("dirty",)

    def __init__(self, idx: int | None, dirty: DirtyExpression, **kwargs):
        super().__init__(idx, **kwargs)
        self.dirty = dirty

    def _hash_core(self):
        return stable_hash((DirtyStatement, self.dirty))

    def __repr__(self):
        return repr(self.dirty)

    def __str__(self):
        return str(self.dirty)

    def replace(self, old_expr, new_expr):
        if self.dirty == old_expr:
            assert isinstance(new_expr, DirtyExpression)
            return True, DirtyStatement(self.idx, new_expr, **self.tags)
        r, new_dirty = self.dirty.replace(old_expr, new_expr)
        if r:
            return True, DirtyStatement(self.idx, new_dirty, **self.tags)
        return False, self

    def copy(self) -> DirtyStatement:
        return DirtyStatement(self.idx, self.dirty, **self.tags)

    def likes(self, other):
        return type(other) is DirtyStatement and self.dirty.likes(other.dirty)

    def matches(self, other):
        return type(other) is DirtyStatement and self.dirty.matches(other.dirty)


class Label(Statement):
    """
    A dummy statement that indicates a label with a name.
    """

    __slots__ = (
        "name",
        "ins_addr",
        "block_idx",
    )

    def __init__(self, idx: int | None, name: str, ins_addr: int, block_idx: int | None = None, **kwargs):
        super().__init__(idx, **kwargs)
        self.name = name
        self.ins_addr = ins_addr
        self.block_idx = block_idx

    def likes(self, other: Label):
        return isinstance(other, Label)

    def replace(self, old_expr, new_expr):
        return False, self

    matches = likes

    def _hash_core(self):
        return stable_hash(
            (
                Label,
                self.name,
                self.ins_addr,
                self.block_idx,
            )
        )

    def __repr__(self):
        return f"Label {self.name}"

    def __str__(self):
        return f"{self.name}:"

    def copy(self) -> Label:
        return Label(self.idx, self.name, self.ins_addr, self.block_idx, **self.tags)
