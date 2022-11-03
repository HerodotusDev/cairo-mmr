%lang starknet

from starkware.cairo.common.pow import pow
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.math_cmp import is_le

func bit_length{range_check_ptr}(num: felt) -> (res: felt) {
    assert_nn(num);
    return bit_length_rec(num, 0);
}

func bit_length_rec{range_check_ptr}(num: felt, current_length: felt) -> (res: felt) {
    let (max) = pow(2, current_length);
    let is_smaller = is_le(num, max - 1);
    if (is_smaller == 1) {
        return (res=current_length);
    }

    return bit_length_rec(num, current_length + 1);
}
