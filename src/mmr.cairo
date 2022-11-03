%lang starknet
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_le
from starkware.cairo.common.cairo_builtins import HashBuiltin

from src.helpers import bit_length, all_ones, bitshift_left

@view
func bag_peaks{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    peaks_len: felt, peaks: felt*
) -> (res: felt) {
    assert_le(1, peaks_len);

    if (peaks_len == 1) {
        return (res=[peaks]);
    }

    let last_peak = [peaks];
    let (rec) = bag_peaks(peaks_len - 1, peaks + 1);

    let (res) = hash2{hash_ptr=pedersen_ptr}(last_peak, rec);

    return (res=res);
}

@view
func height{range_check_ptr}(index: felt) -> (res: felt) {
    alloc_locals;

    assert_le(1, index);

    let (bits) = bit_length(index);
    let (ones) = all_ones(bits);
    if (index != ones) {
        let (shifted) = bitshift_left(1, bits - 1);
        let (rec_height) = height(index - (shifted - 1));
        return (res=rec_height);
    }

    return (res=bits - 1);
}
