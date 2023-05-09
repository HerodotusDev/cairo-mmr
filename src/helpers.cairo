%lang starknet

from starkware.cairo.common.pow import pow
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.math import assert_le
from starkware.cairo.common.alloc import alloc

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

func all_ones{range_check_ptr}(bit_length: felt) -> (res: felt) {
    assert_nn(bit_length);

    let (max) = pow(2, bit_length);
    return (res=max - 1);
}

func bitshift_left{range_check_ptr}(word: felt, num_bits: felt) -> (shifted: felt) {
    // verifies word fits in 64bits
    assert_le(word, 2 ** 64 - 1);

    // verifies shifted bits are not above 64
    assert_le(num_bits, 64);

    let (multiplicator) = pow(2, num_bits);
    let k = word * multiplicator;
    let (q, r) = unsigned_div_rem(k, 2 ** 64);
    return (r,);
}

func array_contains{range_check_ptr}(elem: felt, arr_len: felt, arr: felt*) -> (res: felt) {
    assert_nn(arr_len);

    if (arr_len == 0) {
        return (res=0);
    }
    if ([arr] == elem) {
        return (res=1);
    }

    return array_contains(elem, arr_len - 1, arr + 1);
}

func replace{range_check_ptr}(old_elem: felt, new_elem: felt, arr_len: felt, arr: felt*) -> (res: felt*) {
    alloc_locals;
    assert_nn(arr_len);
    
    let (local res_arr) = alloc();

    return replace_rec(old_elem, new_elem, arr_len, arr, 0, res_arr);
}

func replace_rec{range_check_ptr}(old_elem: felt, new_elem: felt, arr_len: felt, arr: felt*, res_arr_len: felt, res_arr: felt*) -> (res: felt*) {
    if (arr_len == res_arr_len) {
        return (res=res_arr);
    }

    if (arr[res_arr_len] == old_elem) {
        assert res_arr[res_arr_len] = new_elem;
    } else {
        assert res_arr[res_arr_len] = arr[res_arr_len];
    }

    return replace_rec(old_elem, new_elem, arr_len, arr, res_arr_len + 1, res_arr);
}
