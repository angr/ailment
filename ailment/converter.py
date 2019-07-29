import logging

import pyvex
from angr.utils.constants import DEFAULT_STATEMENT
from angr.engines.vex.claripy.irop import vexop_to_simop

from .block import Block
from .statement import Assignment, Store, Jump, Call, ConditionalJump, DirtyStatement, Return
from .expression import Const, Register, Tmp, DirtyExpression, UnaryOp, Convert, BinaryOp, Load, ITE

l = logging.getLogger(name=__name__)


class SkipConversionNotice(Exception):
    pass


class Converter:
    @staticmethod
    def convert(thing):
        raise NotImplementedError()


class VEXExprConverter(Converter):
    @staticmethod
    def generic_name_from_vex_op(vex_op):
        return vexop_to_simop(vex_op)._generic_name

    @staticmethod
    def convert(expr, manager):  # pylint:disable=arguments-differ
        """

        :param expr:
        :return:
        """
        func = EXPRESSION_MAPPINGS.get(type(expr))
        if func is not None:
            return func(expr, manager)

        if isinstance(expr, pyvex.const.IRConst):
            return VEXExprConverter.const_n(expr, manager)

        l.warning("VEXExprConverter: Unsupported VEX expression of type %s.", type(expr))
        return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))

    @staticmethod
    def convert_list(exprs, manager):

        converted = [ ]
        for expr in exprs:
            converted.append(VEXExprConverter.convert(expr, manager))
        return converted

    @staticmethod
    def register(offset, bits, manager):
        reg_size = bits // manager.arch.byte_width
        reg_name = manager.arch.translate_register_name(offset, reg_size)
        return Register(manager.next_atom(), None, offset, bits, reg_name=reg_name,
                        ins_addr=manager.ins_addr,
                        vex_block_addr=manager.block_addr,
                        vex_stmt_idx=manager.vex_stmt_idx,
                        )

    @staticmethod
    def tmp(tmp_idx, bits, manager):
        return Tmp(manager.next_atom(), None, tmp_idx, bits,
                   ins_addr=manager.ins_addr,
                   vex_block_addr=manager.block_addr,
                   vex_stmt_idx=manager.vex_stmt_idx,
                   )

    @staticmethod
    def RdTmp(expr, manager):
        return VEXExprConverter.tmp(expr.tmp, expr.result_size(manager.tyenv), manager)

    @staticmethod
    def Get(expr, manager):
        return VEXExprConverter.register(expr.offset, expr.result_size(manager.tyenv), manager)

    @staticmethod
    def Load(expr, manager):
        return Load(manager.next_atom(),
                    VEXExprConverter.convert(expr.addr, manager),
                    expr.result_size(manager.tyenv) // 8,
                    expr.end,
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=manager.vex_stmt_idx,
                    )

    @staticmethod
    def Unop(expr, manager):
        op_name = VEXExprConverter.generic_name_from_vex_op(expr.op)
        if op_name is None:
            # is it a convertion?
            simop = vexop_to_simop(expr.op)
            if simop._conversion:
                return Convert(manager.next_atom(),
                               simop._from_size,
                               simop._to_size,
                               simop.is_signed,
                               VEXExprConverter.convert(expr.args[0], manager),
                               ins_addr=manager.ins_addr,
                               vex_block_addr=manager.block_addr,
                               vex_stmt_idx=manager.vex_stmt_idx,
                               )
            raise NotImplementedError('Unsupported operation')

        return UnaryOp(manager.next_atom(),
                       op_name,
                       VEXExprConverter.convert(expr.args[0], manager),
                       ins_addr=manager.ins_addr,
                       vex_block_addr=manager.block_addr,
                       vex_stmt_idx=manager.vex_stmt_idx,
                       )

    @staticmethod
    def Binop(expr, manager):
        op = VEXExprConverter.generic_name_from_vex_op(expr.op)
        operands = VEXExprConverter.convert_list(expr.args, manager)

        if op == 'Add' and \
                type(operands[1]) is Const and \
                operands[1].sign_bit == 1:
            # convert it to a sub
            op = 'Sub'
            op1_val, op1_bits = operands[1].value, operands[1].bits
            operands[1] = Const(operands[1].idx, None, (1 << op1_bits) - op1_val, op1_bits)

        signed = False
        if op in {'CmpLE', 'CmpLT', 'CmpGE', 'CmpGT'}:
            if vexop_to_simop(expr.op).is_signed:
                signed = True

        return BinaryOp(manager.next_atom(),
                        op,
                        operands,
                        signed,
                        ins_addr=manager.ins_addr,
                        vex_block_addr=manager.block_addr,
                        vex_stmt_idx=manager.vex_stmt_idx,
                        )

    @staticmethod
    def Const(expr, manager):
        # pyvex.IRExpr.Const
        return Const(manager.next_atom(), None, expr.con.value, expr.result_size(manager.tyenv),
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )

    @staticmethod
    def const_n(expr, manager):
        # pyvex.const.xxx
        return Const(manager.next_atom(), None, expr.value, expr.size,
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )

    @staticmethod
    def ITE(expr, manager):
        cond = VEXExprConverter.convert(expr.cond, manager)
        iffalse = VEXExprConverter.convert(expr.iffalse, manager)
        iftrue = VEXExprConverter.convert(expr.iftrue, manager)

        return ITE(manager.next_atom(), cond, iffalse, iftrue,
                   ins_addr=manager.ins_addr,
                   vex_block_addr=manager.block_addr,
                   vex_stmt_idx=manager.vex_stmt_idx,
                   )

    def CCall(expr, manager):
        if manager.arch.name == "AMD64":
            return AMD64CCallConverter.convert(expr, manager)
        else:
            l.warning("VEXExprConverter: converting %s ccalls is not yet supported.", manager.arch.name)
            return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))


EXPRESSION_MAPPINGS = {
    pyvex.IRExpr.RdTmp: VEXExprConverter.RdTmp,
    pyvex.IRExpr.Get: VEXExprConverter.Get,
    pyvex.IRExpr.Unop: VEXExprConverter.Unop,
    pyvex.IRExpr.Binop: VEXExprConverter.Binop,
    pyvex.IRExpr.Const: VEXExprConverter.Const,
    pyvex.const.U32: VEXExprConverter.const_n,
    pyvex.const.U64: VEXExprConverter.const_n,
    pyvex.IRExpr.Load: VEXExprConverter.Load,
    pyvex.IRExpr.ITE: VEXExprConverter.ITE,
    pyvex.IRExpr.CCall: VEXExprConverter.CCall,
}


class VEXStmtConverter(Converter):

    @staticmethod
    def convert(idx, stmt, manager):  # pylint:disable=arguments-differ
        """

        :param idx:
        :param stmt:
        :param manager:
        :return:
        """

        try:
            func = STATEMENT_MAPPINGS[type(stmt)]
        except KeyError:
            return DirtyStatement(idx, stmt, ins_addr=manager.ins_addr)

        return func(idx, stmt, manager)

    @staticmethod
    def WrTmp(idx, stmt, manager):

        var = VEXExprConverter.tmp(stmt.tmp, stmt.data.result_size(manager.tyenv), manager)
        reg = VEXExprConverter.convert(stmt.data, manager)

        return Assignment(idx, var, reg, ins_addr=manager.ins_addr,
                          vex_block_addr=manager.block_addr,
                          vex_stmt_idx=manager.vex_stmt_idx)

    @staticmethod
    def Put(idx, stmt, manager):
        data = VEXExprConverter.convert(stmt.data, manager)
        reg = VEXExprConverter.register(stmt.offset, data.bits, manager)
        return Assignment(idx, reg, data, ins_addr=manager.ins_addr,
                          vex_block_addr=manager.block_addr,
                          vex_stmt_idx=manager.vex_stmt_idx)

    @staticmethod
    def Store(idx, stmt, manager):

        return Store(idx,
                     VEXExprConverter.convert(stmt.addr, manager),
                     VEXExprConverter.convert(stmt.data, manager),
                     stmt.data.result_size(manager.tyenv) // 8,
                     stmt.endness,
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )

    @staticmethod
    def Exit(idx, stmt, manager):

        if stmt.jumpkind in {'Ijk_EmWarn', 'Ijk_NoDecode',
                              'Ijk_MapFail', 'Ijk_NoRedir',
                              'Ijk_SigTRAP', 'Ijk_SigSEGV',
                              'Ijk_ClientReq'}:
            raise SkipConversionNotice()

        return ConditionalJump(idx,
                               VEXExprConverter.convert(stmt.guard, manager),
                               VEXExprConverter.convert(stmt.dst, manager),
                               None,  # it will be filled in right afterwards
                               ins_addr=manager.ins_addr,
                               vex_block_addr=manager.block_addr,
                               vex_stmt_idx=manager.vex_stmt_idx,
                               )

    @staticmethod
    def LoadG(idx, stmt: pyvex.IRStmt.LoadG, manager):

        sizes = {
            'ILGop_Ident32': (32, 32, False),
            'ILGop_Ident64': (64, 64, False),
            'ILGop_IdentV128': (128, 128, False),
            'ILGop_8Uto32': (8, 32, False),
            'ILGop_8Sto32': (8, 32, True),
            'ILGop_16Uto32': (16, 32, False),
            'ILGop_16Sto32': (16, 32, True),
        }

        dst = VEXExprConverter.tmp(stmt.dst, manager.tyenv.sizeof(stmt.dst) // 8, manager)
        load_bits, convert_bits, signed = sizes[stmt.cvt]
        src = Load(manager.next_atom(),
                   VEXExprConverter.convert(stmt.addr, manager),
                   load_bits // 8,
                   stmt.end,
                   guard=VEXExprConverter.convert(stmt.guard, manager),
                   alt=VEXExprConverter.convert(stmt.alt, manager))
        if convert_bits != load_bits:
            src = Convert(manager.next_atom(), load_bits, convert_bits, signed, src)

        return Assignment(idx, dst, src, ins_addr=manager.ins_addr,
                          vex_block_addr=manager.block_addr,
                          vex_stmt_idx=manager.vex_stmt_idx)

    @staticmethod
    def StoreG(idx, stmt: pyvex.IRStmt.StoreG, manager):

        return Store(idx,
                     VEXExprConverter.convert(stmt.addr, manager),
                     VEXExprConverter.convert(stmt.data, manager),
                     stmt.data.result_size(manager.tyenv) // 8,
                     stmt.endness,
                     guard=VEXExprConverter.convert(stmt.guard, manager),
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )


STATEMENT_MAPPINGS = {
    pyvex.IRStmt.Put: VEXStmtConverter.Put,
    pyvex.IRStmt.WrTmp: VEXStmtConverter.WrTmp,
    pyvex.IRStmt.Store: VEXStmtConverter.Store,
    pyvex.IRStmt.Exit: VEXStmtConverter.Exit,
    pyvex.IRStmt.StoreG: VEXStmtConverter.StoreG,
    pyvex.IRStmt.LoadG: VEXStmtConverter.LoadG,
}


class IRSBConverter(Converter):

    @staticmethod
    def convert(irsb, manager):  # pylint:disable=arguments-differ
        """

        :param irsb:
        :param manager:
        :return:
        """

        # convert each VEX statement into an AIL statement
        statements = [ ]
        idx = 0

        manager.tyenv = irsb.tyenv
        manager.block_addr = irsb.addr

        addr = None

        conditional_jumps = [ ]

        for vex_stmt_idx, stmt in enumerate(irsb.statements):
            if type(stmt) is pyvex.IRStmt.IMark:
                if addr is None:
                    addr = stmt.addr + stmt.delta
                manager.ins_addr = stmt.addr + stmt.delta
                continue
            if type(stmt) is pyvex.IRStmt.AbiHint:
                # TODO: How can we use AbiHint?
                continue

            manager.vex_stmt_idx = vex_stmt_idx
            try:
                converted = VEXStmtConverter.convert(idx, stmt, manager)
                statements.append(converted)
                if type(converted) is ConditionalJump:
                    conditional_jumps.append(converted)
            except SkipConversionNotice:
                pass

            idx += 1

        manager.vex_stmt_idx = DEFAULT_STATEMENT
        if irsb.jumpkind == 'Ijk_Call':
            # call

            # TODO: is there a conditional call?

            ret_reg_offset = manager.arch.ret_offset
            ret_expr = Register(None, None, ret_reg_offset, manager.arch.bits)

            statements.append(Call(manager.next_atom(),
                                   VEXExprConverter.convert(irsb.next, manager),
                                   ret_expr=ret_expr,
                                   ins_addr=manager.ins_addr,
                                   vex_block_addr=manager.block_addr,
                                   vex_stmt_idx=DEFAULT_STATEMENT,
                                   )
                              )
        elif irsb.jumpkind == 'Ijk_Boring':
            if len(conditional_jumps) == 1:
                # fill in the false target
                cond_jump = conditional_jumps[0]
                cond_jump.false_target = VEXExprConverter.convert(irsb.next, manager)

            else:
                # jump
                statements.append(Jump(manager.next_atom(),
                                       VEXExprConverter.convert(irsb.next, manager),
                                       ins_addr=manager.ins_addr,
                                       vex_block_addr=manager.block_addr,
                                       vex_stmt_idx=DEFAULT_STATEMENT,
                                       )
                                  )
        elif irsb.jumpkind == 'Ijk_Ret':
            # return
            statements.append(Return(manager.next_atom(),
                                     VEXExprConverter.convert(irsb.next, manager),
                                     [ ],
                                     ins_addr=manager.ins_addr,
                                     vex_block_addr=manager.block_addr,
                                     vex_stmt_idx=DEFAULT_STATEMENT,
                                     )
                              )

        return Block(addr, irsb.size, statements=statements)


class AMD64CCallConverter(Converter):

    @staticmethod
    def convert(expr, manager):
        ccall_handler = getattr(AMD64CCallConverter, expr.callee.name, None)
        if ccall_handler is not None:
            return ccall_handler(expr, manager)
        else:
            l.warning("AMD64CCallConverter: Unsupported CCall %s.", expr.callee)
            return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))

    @staticmethod
    def get_operand_size(operation):
        """
        Return size of operands of an operation
        """

        if operation[-1] == 'B':
            return 8
        elif operation[-1] == 'W':
            return 16
        elif operation[-1] == 'L':
            return 32
        elif operation[-1] == 'Q':
            return 64

    @staticmethod
    def CondZ(manager, operand, *_):
        return BinaryOp(manager.next_atom(), "CmpEQ", [operand, 0])

    @staticmethod
    def CondNZ(manager, operand, *_):
        return BinaryOp(manager.next_atom(), "CmpNE", [operand, 0])

    @staticmethod
    def CondLE(manager, operand, *_):
        return BinaryOp(manager.next_atom(), "CmpLEs", [operand, 0])

    @staticmethod
    def CondL(manager, operand, *_):
        return BinaryOp(manager.next_atom(), "CmpLTs", [operand, 0])

    @staticmethod
    def CondO(manager, operand, op_is_signed, size):
        shift_op = BinaryOp(manager.next_atom(), "Shr", [operand, size])
        convert_op = Convert(manager.next_atom(), size, 1, op_is_signed, shift_op)
        return AMD64CCallConverter.CondNZ(manager, convert_op)

    @staticmethod
    def CondS(manager, operand, *_):
        return AMD64CCallConverter.CondL(manager, operand)

    @staticmethod
    def amd64g_calculate_condition(expr, manager):
        import angr.engines.vex.ccall as vex_ccall
        cc_cond, cc_op, cc_dep1, cc_dep2, cc_ndep = expr.args
        if cc_op.tag == "Iex_Const":
            vex_op = vex_ccall.data_inverted[manager.arch.name]["OpTypes"][cc_op.con.value]
            if vex_op == "G_CC_OP_COPY" or vex_op == "G_CC_OP_NUMBER":
                l.warning("AMD64CCallConverter: Unsupported operation %s in amd64g_calculate_condition", vex_op)
                return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))
            elif vex_op.startswith("G_CC_OP_LOGIC"):
                l.warning("AMD64CCallConverter: Operation %s not yet supported in amd64g_calculate_condition", vex_op)
                return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))
            else:
                ail_op_str = vex_op.split('_')[-1][:-1].title()
                ail_op_size = AMD64CCallConverter.get_operand_size(vex_op)
                if ail_op_str == "Inc" or ail_op_str == "Dec":
                    ail_operand = VEXExprConverter.convert(cc_dep1, manager)
                    ail_op = UnaryOp(manager.next_atom(), ail_op_str, [ail_operand])
                    ail_op_signed = True
                else:
                    ail_operand1 = VEXExprConverter.convert(cc_dep1, manager)
                    ail_operand2 = VEXExprConverter.convert(cc_dep2, manager)
                    ail_op = BinaryOp(manager.next_atom(), ail_op_str, [ail_operand1, ail_operand2])
                    if ail_op_str.startswith("U"):
                        ail_op_signed = False
                    else:
                        ail_op_signed = True
        else:
            l.warning("AMD64CCallConverter: Unsupported operation type %s in amd64g_calculate_condition", type(cc_op))
            return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))

        if cc_cond.tag == "Iex_Const":
            vex_cond = vex_ccall.data_inverted[manager.arch.name]["CondTypes"][cc_cond.con.value]
            cond_handler = getattr(AMD64CCallConverter, vex_cond, None)
            if cond_handler is not None:
                return cond_handler(manager, ail_op, ail_op_size, ail_op_signed)
            else:
                l.warning("AMD64CCallConverter: Unsupported condition %s", vex_cond)
                return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))
        else:
            l.warning("AMD64CCallConverter: Unsupported condition type %s in amd64g_calculate_condition", type(cc_cond))
            return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))

    @staticmethod
    def amd64g_create_fpucw(expr, manager):
        fpround = VEXExprConverter.convert(expr.args[0], manager)
        op1 = BinaryOp(manager.next_atom(), "BAnd", [fpround, 3])
        op2 = BinaryOp(manager.next_atom(), "Shl", [op1, 10])
        return BinaryOp(manager.next_atom(), "BOr", [op2, 0x37f])

    @staticmethod
    def amd64g_check_fldcw(expr, manager):
        from angr.engines.vex.ccall import EmWarn_X86_x87exns, EmWarn_X86_x87precision, EmNote_NONE
        fpucw = VEXExprConverter.convert(expr.args[0], manager)
        rmode = BinaryOp(manager.next_atom(), "Shr", [fpucw, 10])
        rmode = BinaryOp(manager.next_atom(), "BAnd", [rmode, 3])
        cond_unmasked_exception = BinaryOp(manager.next_atom(), "BAnd", [fpucw, 0x3f])
        cond_unmasked_exception = BinaryOp(manager.next_atom(), "CmpNE", [cond_unmasked_exception, 0x3f])
        res_unmasked_exception = Const(manager.next_atom(), None, EmWarn_X86_x87exns, 8)
        cond_precision = BinaryOp(manager.next_atom(), "Shr", [fpucw, 8])
        cond_precision = BinaryOp(manager.next_atom(), "BAnd", [cond_precision, 3])
        cond_precision = BinaryOp(manager.next_atom(), "CmpNE", [cond_precision, 3])
        res_precision = Const(manager.next_atom(), None, EmWarn_X86_x87precision, 8)
        res_default = Const(manager.next_atom(), None, EmNote_NONE, 8)
        ite1 = ITE(manager.next_atom(), cond_unmasked_exception, res_default, res_unmasked_exception)
        ite2 = ITE(manager.next_atom(), cond_precision, ite1, res_precision)
        final_res = BinaryOp(manager.next_atom(), "Shl", [ite2, 32])
        final_res = BinaryOp(manager.next_atom(), "BOr", [final_res, rmode])
        return final_res
