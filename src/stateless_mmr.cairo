%lang starknet
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_le, assert_nn_le, assert_nn
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin

from src.helpers import bit_length, all_ones, bitshift_left, array_contains

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
func compute_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    peaks_len: felt, peaks: felt*, size: felt
) -> (res: felt) {
    let (bagged_peaks) = bag_peaks(peaks_len, peaks);
    let (root) = hash2{hash_ptr=pedersen_ptr}(size, bagged_peaks);

    return (res=root);
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
func multi_append{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    elems_len: felt, elems: felt*, peaks_len: felt, peaks: felt*, last_pos: felt, last_root: felt
) -> (new_pos: felt, new_root: felt) {
    return multi_append_rec(elems_len, elems, peaks_len, peaks, last_pos, last_root);
}

func multi_append_rec{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    elems_len: felt,
    elems: felt*,
    last_peaks_len: felt,
    last_peaks: felt*,
    last_pos: felt,
    last_root: felt,
) -> (new_pos: felt, new_root: felt) {
    alloc_locals;

    let elem = [elems];
    let pos = last_pos + 1;
    if (last_pos == 0) {
        let (root0) = hash2{hash_ptr=pedersen_ptr}(1, elem);
        let (root) = hash2{hash_ptr=pedersen_ptr}(1, root0);
        if (elems_len == 1) {
            return (new_pos=pos, new_root=root);
        }
        let (local peaks: felt*) = alloc();
        assert peaks[0] = root0;
        return multi_append_rec(elems_len - 1, elems + 1, 1, peaks, pos, root);
    }

    let (computed_root) = compute_root(last_peaks_len, last_peaks, last_pos);
    assert computed_root = last_root;

    let (hash) = hash2{hash_ptr=pedersen_ptr}(pos, elem);

    let (local append_peak) = alloc();
    memcpy(append_peak, last_peaks, last_peaks_len);
    assert append_peak[last_peaks_len] = hash;

    let (peaks_len, peaks, new_pos) = append_rec(0, last_peaks_len + 1, append_peak, pos);
    let (new_root) = compute_root(peaks_len, peaks, new_pos);
    if (elems_len == 1) {
        return (new_pos=new_pos, new_root=new_root);
    }
    return multi_append_rec(elems_len - 1, elems + 1, peaks_len, peaks, new_pos, new_root);
}

@external
func append{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    elem: felt, peaks_len: felt, peaks: felt*, last_pos: felt, last_root: felt
) -> (new_pos: felt, new_root: felt) {
    alloc_locals;

    let pos = last_pos + 1;
    if (last_pos == 0) {
        let (root0) = hash2{hash_ptr=pedersen_ptr}(1, elem);
        let (root) = hash2{hash_ptr=pedersen_ptr}(1, root0);
        return (new_pos=pos, new_root=root);
    }

    let (computed_root) = compute_root(peaks_len, peaks, last_pos);
    assert computed_root = last_root;

    let (hash) = hash2{hash_ptr=pedersen_ptr}(pos, elem);

    let (local append_peak) = alloc();
    memcpy(append_peak, peaks, peaks_len);
    assert append_peak[peaks_len] = hash;

    let (peaks_len, peaks, new_pos) = append_rec(0, peaks_len + 1, append_peak, pos);
    let (new_root) = compute_root(peaks_len, peaks, new_pos);
    return (new_pos=new_pos, new_root=new_root);
}

func append_rec{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    h: felt, peaks_len: felt, peaks: felt*, last_pos: felt
) -> (p_len: felt, p: felt*, new_pos: felt) {
    alloc_locals;

    let pos = last_pos;
    let (next_height) = height(pos + 1);

    let is_higher = is_le(h + 1, next_height);
    if (is_higher == 1) {
        let pos = pos + 1;

        let right_hash = peaks[peaks_len - 1];
        let left_hash = peaks[peaks_len - 2];
        let peaks_len = peaks_len - 2;

        let (hash) = hash2{hash_ptr=pedersen_ptr}(left_hash, right_hash);

        let (parent_hash) = hash2{hash_ptr=pedersen_ptr}(pos, hash);

        let (local merged_peaks) = alloc();
        memcpy(merged_peaks, peaks, peaks_len);
        assert merged_peaks[peaks_len] = parent_hash;

        return append_rec(h + 1, peaks_len + 1, merged_peaks, pos);
    }
    return (p_len=peaks_len, p=peaks, new_pos=pos);
}

@view
func verify_proof{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    index: felt,
    value: felt,
    proof_len: felt,
    proof: felt*,
    peaks_len: felt,
    peaks: felt*,
    pos: felt,
    root: felt,
) {
    alloc_locals;

    assert_nn_le(index, pos);

    let (computed_root) = compute_root(peaks_len, peaks, pos);
    assert computed_root = root;

    let (hash) = hash2{hash_ptr=pedersen_ptr}(index, value);

    let (peak) = verify_proof_rec(0, hash, index, proof_len, proof);
    let (valid) = array_contains(peak, peaks_len, peaks);

    assert valid = 1;
    return ();
}

func verify_proof_rec{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    h: felt, hash: felt, pos: felt, proof_len: felt, proof: felt*
) -> (res: felt) {
    alloc_locals;

    if (proof_len == 0) {
        return (res=hash);
    }

    let current_sibling = [proof];
    let (current_height) = height(pos);
    let (next_height) = height(pos + 1);

    let is_higher = is_le(h + 1, next_height);

    local new_hash;
    local new_pos;
    if (is_higher == 1) {
        // right child
        let (hashed) = hash2{hash_ptr=pedersen_ptr}(current_sibling, hash);
        new_pos = pos + 1;

        let (parent_hash) = hash2{hash_ptr=pedersen_ptr}(new_pos, hashed);
        new_hash = parent_hash;

        tempvar pedersen_ptr = pedersen_ptr;
        tempvar range_check_ptr = range_check_ptr;
    } else {
        // left child
        let (hashed) = hash2{hash_ptr=pedersen_ptr}(hash, current_sibling);
        let (shifted) = bitshift_left(2, h);
        new_pos = pos + shifted;

        let (parent_hash) = hash2{hash_ptr=pedersen_ptr}(new_pos, hashed);
        new_hash = parent_hash;

        tempvar pedersen_ptr = pedersen_ptr;
        tempvar range_check_ptr = range_check_ptr;
    }

    return verify_proof_rec(h + 1, new_hash, new_pos, proof_len - 1, proof + 1);
}
