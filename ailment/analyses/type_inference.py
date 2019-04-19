from collections import namedtuple

from angr import Analysis, register_analysis
from angr.analyses.forward_analysis import (ForwardAnalysis,
                                            FunctionGraphVisitor,
                                            SingleNodeGraphVisitor)
from angr.engines.light import SimEngineLightAIL


def recordtuple(name, *args, **kwargs):
    thenamedtuple = namedtuple(name, *args, **kwargs)

    oldhash = thenamedtuple.__hash__

    def improved_hash_function(self):
        return hash((oldhash(self), name))

    thenamedtuple.__hash__ = improved_hash_function

    oldeq = thenamedtuple.__eq__

    def improved_equal_function(self, other):
        return oldeq(self, other) and type(self) == type(other)

    thenamedtuple.__eq__ = improved_equal_function

    return type(name, (thenamedtuple, ), {
        '__hash__': improved_hash_function,
        '__eq__': improved_equal_function
    })

EqualityConstraint = recordtuple('EqualityConstraint', ['lhs', 'rhs'])
TmpTypeVar = recordtuple('TmpTypeVar', ['block', 'idx'])

class SimEngineTypeConstraintCollector(SimEngineLightAIL):
    def __init__(self, arch):
        super().__init__()
        self.constraints = set()
        self._arch = arch

    def _add_constraint(self, lhs, rhs):
        if lhs is not None and rhs is not None:
            self.constraints.add(EqualityConstraint(lhs, rhs))

    def _ail_handle_Tmp(self, tmp):
        return TmpTypeVar(self.block, tmp.tmp_idx)

    def _ail_handle_Const(self, expr):
        pass

    def _ail_handle_StackBaseOffset(self, expr):
        pass

    def _handle_Const(self, expr):
        raise Exception('really?')

    def _ail_handle_Assignment(self, stmt):
        rhs_tyvar = self._expr(stmt.src)
        lhs_tyvar = self._expr(stmt.dst)
        self._add_constraint(lhs_tyvar, rhs_tyvar)

    def _ail_handle_Call(self, stmt):
        if stmt.prototype is not None:
            proto = stmt.prototype.with_arch(self._arch)
            for arg, arg_ty in zip(stmt.args, proto.args):
                print(arg)
                arg_tyvar = self._expr(arg)
                self._add_constraint(arg_tyvar, arg_ty)
            if stmt.ret_expr is not None:
                ret_tyvar = self._expr(stmt.ret_expr)
                self._add_constraint(ret_tyvar, proto.returnty)

    def _ail_handle_Jump(self, stmt):
        pass

    def _ail_handle_Load(self, stmt):
        pass

class TypeInference(Analysis):
    def __init__(self, func=None, block=None, graph=None):
        if func is not None:
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, graph)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('Cannot find function or block to analyze')

        ForwardAnalysis.__init__(self, graph_visitor=graph_visitor)
        self._engine = SimEngineTypeConstraintCollector(self.project.arch)
        self._analyze()

    def _analyze(self):
        while True:
            n = self._graph_visitor.next_node()

            if n is None:
                break

            self._engine.process(None, block=n)

    @property
    def constraints(self):
        return set(self._engine.constraints)

register_analysis(TypeInference, 'TypeInference')
