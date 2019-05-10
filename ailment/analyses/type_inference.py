import logging
from collections import defaultdict, namedtuple

from ailment.datalog import solve_types
from angr import Analysis, register_analysis
from angr.analyses.forward_analysis import (ForwardAnalysis,
                                            FunctionGraphVisitor,
                                            SingleNodeGraphVisitor)
from angr.engines.light import SimEngineLightAIL
from angr.knowledge_plugins import KnowledgeBasePlugin

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)

class EqualityConstraint:
    def __init__(self, lhs, rhs):
        self.lhs = lhs
        self.rhs = rhs

    def __hash__(self):
        return hash((EqualityConstraint, self.lhs, self.rhs))

    def __eq__(self, other):
        return self.lhs == other.lhs and self.rhs == other.rhs and isinstance(other, EqualityConstraint)

    def to_datalog(self):
        if type(self.lhs) is WidthType and type(self.rhs) is VarTypeVar:
            return 'has_type', (self.rhs, self.lhs)
        elif type(self.lhs) is VarTypeVar and type(self.rhs) is WidthType:
            return 'has_type', (self.lhs, self.rhs)
        elif type(self.lhs) is VarTypeVar and type(self.rhs) is VarTypeVar:
            return 'eq', (self.lhs, self.rhs)

    def __repr__(self):
        return '{} = {}'.format(self.lhs, self.rhs)

class VarTypeVar:
    def __init__(self, var):
        self.var = var

    def __hash__(self):
        return hash((VarTypeVar, self.var))

    def __eq__(self, other):
        return self.var == other.var and isinstance(other, VarTypeVar)

    def __repr__(self):
        return '{}({})'.format(VarTypeVar.__name__, self.var)

class WidthType:
    def __init__(self, bits):
        self.bits = bits

    def __hash__(self):
        return hash((WidthType, self.bits))

    def __eq__(self, other):
        return self.bits == other.bits and isinstance(other, WidthType)

    def __repr__(self):
        return '{}({})'.format(WidthType.__name__, self.bits)

class FunctionReturnTypeVar:
    def __init__(self, func):
        self.func = func

    def __hash__(self):
        return hash((FunctionReturnTypeVar.__name__, self.func))

    def __eq__(self, other):
        return self.func == other.func and type(self) == type(other)

    def __repr__(self):
        return '{}->return'.format(self.func.name)

class FunctionArgumentType:
    def __init__(self, func, arg_idx):
        self.func = func
        self.arg_idx = arg_idx

    def __hash__(self):
        return hash((FunctionArgumentType.__name__, self.func))

    def __eq__(self, other):
        return self.func == other.func and type(self) == type(other)

    def __repr__(self):
        return '{}->arg{}'.format(self.func, self.arg_idx)

class SimEngineTypeConstraintCollector(SimEngineLightAIL):
    def __init__(self, arch):
        super().__init__()
        self.constraints = set()
        self._arch = arch

    def _add_constraint(self, lhs, rhs):
        if lhs is not None and rhs is not None:
            self.constraints.add(EqualityConstraint(lhs, rhs))

    def _ail_handle_Tmp(self, tmp):
        return VarTypeVar(tmp.variable)

    def _ail_handle_Const(self, expr):
        return WidthType(expr.bits)

    def _ail_handle_Register(self, expr):
        if expr.variable is not None:
            v = VarTypeVar(expr.variable)
            self._add_constraint(v, WidthType(expr.bits))
            return v
        else:
            return WidthType(expr.bits)

    def _ail_handle_StackBaseOffset(self, expr):
        return WidthType(expr.bits)

    def _ail_handle_Convert(self, expr):
        operand = self._expr(expr.operand)
        self._add_constraint(operand, WidthType(expr.from_bits))
        return WidthType(expr.to_bits)

    def _ail_handle_Assignment(self, stmt):
        rhs_tyvar = self._expr(stmt.src)
        lhs_tyvar = self._expr(stmt.dst)
        self._add_constraint(lhs_tyvar, rhs_tyvar)

    def _ail_handle_Call(self, stmt):
        _l.debug('Detected call at 0x%x', stmt.ins_addr)
        if stmt.ins_addr == 0x4007c2:
            breakpoint()
        if stmt.args is None:
            return
        if stmt.prototype is not None:
            proto = stmt.prototype.with_arch(self._arch)
            for arg, arg_ty in zip(stmt.args, proto.args):
                arg_tyvar = self._expr(arg)
                self._add_constraint(arg_tyvar, arg_ty)
            if stmt.ret_expr is not None:
                ret_tyvar = self._expr(stmt.ret_expr)
                self._add_constraint(ret_tyvar, proto.returnty)
        else:
            for i, v in enumerate(stmt.args):
                v_tyvar = self._expr(v)
                func_arg = FunctionArgumentType(stmt.target, i)
                self._add_constraint(v_tyvar, func_arg)

    def _ail_handle_Store(self, stmt):
        if stmt.variable is not None:
            data = self._expr(stmt.data)
            v = VarTypeVar(stmt.variable)
            self._add_constraint(v, data)

    def _ail_handle_Jump(self, stmt):
        pass

    def _ail_handle_Load(self, stmt):
        pass

class TypeConstraintGenerator(Analysis):
    def __init__(self, func, graph=None):
        self._func = func
        self._graph_visitor = FunctionGraphVisitor(func, graph)
        self._engine = SimEngineTypeConstraintCollector(self.project.arch)
        self._analyze()

    def _analyze(self):
        while True:
            n = self._graph_visitor.next_node()

            if n is None:
                break

            self._engine.process(None, block=n)
        if self.kb is not None:
            self.kb.type_constraints[self._func.addr] = self._engine.constraints.copy()

    @property
    def constraints(self):
        return set(self._engine.constraints)

class TypeConstraintManager(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__()
        self._kb = kb
        self._constraints = {}

    def __getitem__(self, addr):
        return self._constraints[addr]

    def __contains__(self, addr):
        return addr in self._constraints

    def __setitem__(self, addr, constraints):
        self._constraints[addr] = constraints

    def copy(self):
        raise NotImplementedError

class TypeInference(Analysis):
    def __init__(self, funcs=None):
        if funcs is None:
            self._funcs = list(f for f in self.kb.functions if f in self.kb.type_constraints)
        else:
            self._funcs = funcs
        self._mapping = {}
        self._analyze()

    def _analyze(self):

        def fresh():
            return len(_pytodl)

        _pytodl = defaultdict(fresh)
        _dltopy = {}

        def pytodl(py):
            dl = 'v{}'.format(_pytodl[py])
            _dltopy[dl] = py
            return dl

        def dltopy(dl):
            return _dltopy[dl]

        all_constraints = []
        for f_addr in self._funcs:
            constraints = self.kb.type_constraints[f_addr]
            all_constraints.extend(constraints)
        dl_facts = defaultdict(list)
        for c in all_constraints:
            dl_repres = c.to_datalog()
            if dl_repres is None:
                continue
            else:
                rel, params = dl_repres
            dl_params = tuple(pytodl(p) for p in params)
            dl_facts[rel].append(dl_params)
        solved = solve_types(dict(dl_facts))
        ty_mapping = {}
        for var_dl, ty_dl in solved['has_type']:
            var_py = dltopy(var_dl)
            ty_py = dltopy(ty_dl)
            if var_py in ty_mapping and ty_py == ty_mapping[var_py]:
                ty_mapping[var_py] = None
            else:
                ty_mapping[var_py] = ty_py
        self._mapping = ty_mapping
        self.kb.types._mapping = dict(self._mapping)

class VariableTypeManager(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__()
        self._kb = kb
        self._mapping = {}

    def __getitem__(self, var):
        return self._mapping[var]

    def __setitem__(self, var, ty):
        self._mapping[var] = ty

    def copy(self):
        raise NotImplementedError




register_analysis(TypeConstraintGenerator, 'TypeConstraints')
KnowledgeBasePlugin.register_default('type_constraints', TypeConstraintManager)

register_analysis(TypeInference, 'TypeInference')
KnowledgeBasePlugin.register_default('types', VariableTypeManager)
