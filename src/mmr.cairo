%lang starknet
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_le
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.cairo_builtins import HashBuiltin

from src.helpers import bit_length, all_ones, bitshift_left

@storage_var
func _root() -> (res: felt) {
}

@storage_var
func _last_pos() -> (res: felt) {
}

@view
func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    return _root.read();
}

@view
func get_last_pos{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    return _last_pos.read();
}

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

@external
func append{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(elem: felt, peaks_len: felt, peaks: felt*) {
    alloc_locals;

    let (pos) = _last_pos.read();
    _last_pos.write(pos + 1);

    if (pos == 0) {
        let (root) = hash2{hash_ptr=pedersen_ptr}(1, elem);
        _root.write(root);
        return ();
    }

    let (bagged_peaks) = bag_peaks(peaks_len, peaks);
    let (root) = _root.read();
    assert bagged_peaks = root;

    let (current_pos) = _last_pos.read();
    let (hash) = hash2{hash_ptr=pedersen_ptr}(current_pos, elem);

    assert peaks[peaks_len] = hash;
    let peaks_len = peaks_len + 1;

    append_rec(0, peaks_len, peaks);

    let (new_root) = bag_peaks(peaks_len, peaks);
    _root.write(new_root);

    return ();
}

func append_rec{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(h: felt, peaks_len: felt, peaks: felt*) {
    alloc_locals;

    let (pos) = _last_pos.read();
    let (next_height) = height(pos+1);
    
    let is_higher = is_le(h+1, next_height);
    if (is_higher == 1) {
        _last_pos.write(pos+1);

        let right_hash = peaks[peaks_len - 1];
        let left_hash = peaks[peaks_len - 2];
        let peaks_len = peaks_len - 2;
        
        let (hash) = hash2{hash_ptr=pedersen_ptr}(left_hash, right_hash);

        let (current_pos) = _last_pos.read();
        let (parent_hash) = hash2{hash_ptr=pedersen_ptr}(current_pos, hash);

        assert peaks[peaks_len] = parent_hash;
        let peaks_len = peaks_len + 1;

        return append_rec(h+1, peaks_len, peaks);
    }

    return ();
}
