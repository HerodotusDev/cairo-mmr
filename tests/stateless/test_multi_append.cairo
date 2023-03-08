%lang starknet
from src.stateless_mmr import multi_append
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc

@external
func test_multi_append_single_element{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;
    let (elems: felt*) = alloc();
    assert elems[0] = 1;

    let (local peaks: felt*) = alloc();

    let (new_pos, new_root) = multi_append(
        elems_len=1, elems=elems, peaks_len=0, peaks=peaks, last_pos=0, last_root=0
    );
    assert new_pos = 1;
    return ();
}

@external
func test_multi_append_2_elements{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    ) {
    alloc_locals;
    let (elems: felt*) = alloc();
    assert elems[0] = 1;
    assert elems[1] = 2;

    let (local peaks: felt*) = alloc();

    let (new_pos, new_root) = multi_append(
        elems_len=2, elems=elems, peaks_len=0, peaks=peaks, last_pos=0, last_root=0
    );
    assert new_pos = 3;
    return ();
}

@external
func test_multi_append_3_elements{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    ) {
    alloc_locals;
    let (elems: felt*) = alloc();
    assert elems[0] = 1;
    assert elems[1] = 2;
    assert elems[2] = 3;

    let (local peaks: felt*) = alloc();

    let (new_pos, new_root) = multi_append(
        elems_len=3, elems=elems, peaks_len=0, peaks=peaks, last_pos=0, last_root=0
    );
    assert new_pos = 4;
    return ();
}

@external
func test_multi_append_4_elements{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    ) {
    alloc_locals;
    let (elems: felt*) = alloc();
    assert elems[0] = 1;
    assert elems[1] = 2;
    assert elems[2] = 3;
    assert elems[3] = 4;

    let (local peaks: felt*) = alloc();

    let (new_pos, new_root) = multi_append(
        elems_len=4, elems=elems, peaks_len=0, peaks=peaks, last_pos=0, last_root=0
    );
    assert new_pos = 7;
    return ();
}

@external
func test_multi_append_5_elements{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    ) {
    alloc_locals;
    let (elems: felt*) = alloc();
    assert elems[0] = 1;
    assert elems[1] = 2;
    assert elems[2] = 3;
    assert elems[3] = 4;
    assert elems[4] = 5;

    let (local peaks: felt*) = alloc();

    let (new_pos, new_root) = multi_append(
        elems_len=5, elems=elems, peaks_len=0, peaks=peaks, last_pos=0, last_root=0
    );
    assert new_pos = 8;
    return ();
}
