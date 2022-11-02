%lang starknet
from src.main import bag_peaks
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.hash import hash2

@external
func test_bag_peaks_1{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (peak0) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    assert peaks[0] = peak0;

    let (res) = bag_peaks(1, peaks);
    assert res = peak0;
    return ();
}

@external
func test_bag_peaks_2{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (peak0) = hash2{hash_ptr=pedersen_ptr}(1, 843984);
    let (peak1) = hash2{hash_ptr=pedersen_ptr}(7, 38474983);

    assert peaks[0] = peak0;
    assert peaks[1] = peak1;

    let (root) = hash2{hash_ptr=pedersen_ptr}(peak0, peak1);

    let (res) = bag_peaks(2, peaks);
    assert res = root;
    return ();
}

@external
func test_bag_peaks_3{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (peak0) = hash2{hash_ptr=pedersen_ptr}(245, 2480);
    let (peak1) = hash2{hash_ptr=pedersen_ptr}(2340, 23428);
    let (peak2) = hash2{hash_ptr=pedersen_ptr}(923048, 283409);

    assert peaks[0] = peak0;
    assert peaks[1] = peak1;
    assert peaks[2] = peak2;

    let (root0) = hash2{hash_ptr=pedersen_ptr}(peak1, peak2);
    let (root) = hash2{hash_ptr=pedersen_ptr}(peak0, root0);

    let (res) = bag_peaks(3, peaks);
    assert res = root;
    return ();
}
