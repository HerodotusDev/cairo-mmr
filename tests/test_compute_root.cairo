%lang starknet
from src.mmr import compute_root
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.hash import hash2

@external
func test_compute_root_empty{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    %{ expect_revert() %}
    compute_root(0, peaks, 0);
    return ();
}

@external
func test_compute_root_1{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (peak0) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    assert peaks[0] = peak0;

    let (root) = hash2{hash_ptr=pedersen_ptr}(1, peak0);

    let (res) = compute_root(1, peaks, 1);
    assert res = root;
    return ();
}

@external
func test_compute_root_2{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (peak0) = hash2{hash_ptr=pedersen_ptr}(1, 843984);
    let (peak1) = hash2{hash_ptr=pedersen_ptr}(7, 38474983);

    assert peaks[0] = peak0;
    assert peaks[1] = peak1;

    let (root0) = hash2{hash_ptr=pedersen_ptr}(peak0, peak1);
    let (root) = hash2{hash_ptr=pedersen_ptr}(7, root0);

    let (res) = compute_root(2, peaks, 7);
    assert res = root;
    return ();
}

@external
func test_compute_root_3{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (peak0) = hash2{hash_ptr=pedersen_ptr}(245, 2480);
    let (peak1) = hash2{hash_ptr=pedersen_ptr}(2340, 23428);
    let (peak2) = hash2{hash_ptr=pedersen_ptr}(923048, 283409);

    assert peaks[0] = peak0;
    assert peaks[1] = peak1;
    assert peaks[2] = peak2;

    let (root0) = hash2{hash_ptr=pedersen_ptr}(peak1, peak2);
    let (root1) = hash2{hash_ptr=pedersen_ptr}(peak0, root0);
    let (root) = hash2{hash_ptr=pedersen_ptr}(923048, root1);

    let (res) = compute_root(3, peaks, 923048);
    assert res = root;
    return ();
}
