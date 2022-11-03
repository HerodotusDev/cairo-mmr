%lang starknet
from src.mmr import height
from starkware.cairo.common.cairo_builtins import HashBuiltin

@external
func test_height_revert{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    %{ expect_revert() %}
    height(0);
    return ();
}

@external
func test_height{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let (height0) = height(1);
    assert height0 = 0;

    let (height1) = height(2);
    assert height1 = 0;

    let (height2) = height(3);
    assert height2 = 1;

    let (height3) = height(7);
    assert height3 = 2;

    let (height4) = height(8);
    assert height4 = 0;

    let (height5) = height(46);
    assert height5 = 3;

    let (height6) = height(46);
    assert height6 = 3;

    let (height7) = height(49);
    assert height7 = 1;

    return ();
}
