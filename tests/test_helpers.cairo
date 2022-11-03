%lang starknet
from src.helpers import bit_length
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
