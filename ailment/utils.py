from typing import Union, Optional, TYPE_CHECKING

import claripy
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

if TYPE_CHECKING:
    from .expression import Expression


def get_bits(expr: Union[claripy.ast.Bits,'Expression',int]) -> Optional[int]:
    # delayed import
    from .expression import Expression

    if isinstance(expr, Expression):
        return expr.bits
    if isinstance(expr, MultiValues):
        return get_bits(expr.one_value())
    elif isinstance(expr, claripy.ast.Bits):
        return expr.size()
    elif hasattr(expr, 'bits'):
        return expr.bits
    else:
        return None
