%lang starknet
from src.helpers import bit_length, all_ones, array_contains
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin

@external
func test_bit_length_negative{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    %{ expect_revert() %}
    bit_length(-1);
    return ();
}

@external
func test_bit_length{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let (length0) = bit_length(0);
    assert length0 = 0;

    let (length1) = bit_length(1);
    assert length1 = 1;

    let (length2) = bit_length(2);
    assert length2 = 2;

    let (length3) = bit_length(5);
    assert length3 = 3;

    let (length4) = bit_length(7);
    assert length4 = 3;

    let (length5) = bit_length(8);
    assert length5 = 4;

    return ();
}

@external
func test_all_ones_negative{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    %{ expect_revert() %}
    all_ones(-1);
    return ();
}

@external
func test_all_ones{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let (ones0) = all_ones(0);
    assert ones0 = 0;

    let (ones1) = all_ones(1);
    assert ones1 = 1;

    let (ones2) = all_ones(2);
    assert ones2 = 3;

    let (ones3) = all_ones(3);
    assert ones3 = 7;

    let (ones4) = all_ones(4);
    assert ones4 = 15;

    return ();
}

@external
func test_array_contains_negative{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local arr) = alloc();

    %{ expect_revert() %}
    array_contains(1, -1, arr);
    return ();
}

@external
func test_array_contains{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local arr) = alloc();

    let (res) = array_contains(0, 0, arr);
    assert res = 0;

    assert arr[0] = 1;
    let (res) = array_contains(0, 1, arr);
    assert res = 0;
    let (res) = array_contains(1, 1, arr);
    assert res = 1;

    assert arr[1] = 2;
    let (res) = array_contains(0, 2, arr);
    assert res = 0;
    let (res) = array_contains(1, 2, arr);
    assert res = 1;
    let (res) = array_contains(2, 2, arr);
    assert res = 1;

    return ();
}
