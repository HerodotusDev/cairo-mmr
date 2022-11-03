%lang starknet
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_le
from starkware.cairo.common.cairo_builtins import HashBuiltin

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
