__version__ = "9.2.25"

import logging
from typing import Set

from .block import Block
from . import statement as Stmt
from . import expression as Expr
from .statement import Assignment
from .expression import Expression, Const, Tmp, Register, UnaryOp, BinaryOp
from .converter_common import Converter
from .manager import Manager

log = logging.getLogger(__name__)


available_converters: Set[str] = set()

try:
    from .converter_vex import VEXIRSBConverter
    import pyvex
    available_converters.add("vex")
except ImportError as e:
    log.debug("Could not import VEXIRSBConverter")
    log.debug(e)

try:
    from .converter_pcode import PCodeIRSBConverter
    from angr.engines import pcode
    available_converters.add("pcode")
except ImportError as e:
    log.debug("Could not import PCodeIRSBConverter")
    log.debug(e)


class IRSBConverter(Converter):
    @staticmethod
    def convert(irsb, manager):  # pylint:disable=arguments-differ
        """
        Convert the given IRSB to an AIL block

        :param irsb:    The IRSB to convert
        :param manager: The manager to use
        :return:        Returns the converted block
        """

        if "pcode" in available_converters and isinstance(irsb, pcode.lifter.IRSB):
            return PCodeIRSBConverter.convert(irsb, manager)
        elif "vex" in available_converters and isinstance(irsb, pyvex.IRSB):
            return VEXIRSBConverter.convert(irsb, manager)
        else:
            raise ValueError("No converter available for %s" % type(irsb))
