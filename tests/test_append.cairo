%lang starknet
from src.mmr import append, get_root, get_last_pos
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc

@external
func test_append_initial{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();
    
    append(elem=1, peaks_len=0, peaks=peaks);
    let (node) = hash2{hash_ptr=pedersen_ptr}(1, 1);

    let (last_pos) = get_last_pos();
    let (root) = get_root();
    assert last_pos = 1;
    assert root = node;

    return ();
}

@external
func test_append_pos_1{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (last_pos) = get_last_pos();
    
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);
    
    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (last_pos) = get_last_pos();
    assert last_pos = 2;

    return ();
}
