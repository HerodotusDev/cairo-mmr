%lang starknet
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_le, assert_nn_le, assert_nn
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin

from src.helpers import bit_length, all_ones, bitshift_left, array_contains

@storage_var
func _root() -> (res: felt) {
}

@storage_var
func _last_pos() -> (res: felt) {
}

@storage_var
func _tree_size_to_root(tree_size: felt) -> (res: felt) {
}

@view
func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    return _root.read();
}

@view
func get_last_pos{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _last_pos.read();
}

@view
func get_tree_size_to_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    tree_size: felt
) -> (res: felt) {
    return _tree_size_to_root.read(tree_size);
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
func append{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    elem: felt, peaks_len: felt, peaks: felt*
) -> (pos: felt) {
    alloc_locals;

    let (pos) = _last_pos.read();
    _last_pos.write(pos + 1);

    if (pos == 0) {
        let (root0) = hash2{hash_ptr=pedersen_ptr}(1, elem);
        let (root) = hash2{hash_ptr=pedersen_ptr}(1, root0);
        _tree_size_to_root.write(1, root);
        _root.write(root);
        return (pos=1);
    }

    let (computed_root) = compute_root(peaks_len, peaks, pos);
    let (root) = _root.read();
    assert computed_root = root;

    let (current_pos) = _last_pos.read();
    let (hash) = hash2{hash_ptr=pedersen_ptr}(current_pos, elem);

    let (local append_peak) = alloc();
    memcpy(append_peak, peaks, peaks_len);
    assert append_peak[peaks_len] = hash;

    let (peaks_len, peaks) = append_rec(0, peaks_len + 1, append_peak);

    let (new_pos) = _last_pos.read();
    let (new_root) = compute_root(peaks_len, peaks, new_pos);
    _tree_size_to_root.write(new_pos, new_root);
    _root.write(new_root);

    return (pos=new_pos);
}

func append_rec{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    h: felt, peaks_len: felt, peaks: felt*
) -> (p_len: felt, p: felt*) {
    alloc_locals;

    let (pos) = _last_pos.read();
    let (next_height) = height(pos + 1);

    let is_higher = is_le(h + 1, next_height);
    if (is_higher == 1) {
        _last_pos.write(pos + 1);

        let right_hash = peaks[peaks_len - 1];
        let left_hash = peaks[peaks_len - 2];
        let peaks_len = peaks_len - 2;

        let (hash) = hash2{hash_ptr=pedersen_ptr}(left_hash, right_hash);

        let (current_pos) = _last_pos.read();
        let (parent_hash) = hash2{hash_ptr=pedersen_ptr}(current_pos, hash);

        let (local merged_peaks) = alloc();
        memcpy(merged_peaks, peaks, peaks_len);
        assert merged_peaks[peaks_len] = parent_hash;

        return append_rec(h + 1, peaks_len + 1, merged_peaks);
    }

    return (p_len=peaks_len, p=peaks);
}

@view
func verify_past_proof{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    index: felt,
    value: felt,
    proof_len: felt,
    proof: felt*,
    peaks_len: felt,
    peaks: felt*,
    pos: felt,
) {
    alloc_locals;
    let (computed_root) = compute_root(peaks_len, peaks, pos);
    let (root) = _tree_size_to_root.read(pos);
    assert computed_root = root;

    let (hash) = hash2{hash_ptr=pedersen_ptr}(index, value);

    let (peak) = verify_proof_rec(0, hash, index, proof_len, proof);
    let (valid) = array_contains(peak, peaks_len, peaks);

    assert valid = 1;
    return ();
}

@view
func verify_proof{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    index: felt, value: felt, proof_len: felt, proof: felt*, peaks_len: felt, peaks: felt*
) {
    alloc_locals;

    let (pos) = _last_pos.read();
    assert_nn_le(index, pos);

    let (computed_root) = compute_root(peaks_len, peaks, pos);
    let (root) = _root.read();
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
