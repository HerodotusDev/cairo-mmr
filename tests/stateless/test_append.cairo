%lang starknet
from src.stateless_mmr import append
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.alloc import alloc

@external
func test_append_initial{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (new_pos, new_root) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);
    let (node) = hash2{hash_ptr=pedersen_ptr}(1, 1);

    assert new_pos = 1;

    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(1, node);
    assert new_root = computed_root;

    return ();
}

@external
func test_append_1{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos, new_root) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);
    assert new_pos = 1;

    assert peaks[0] = node1;
    let (new_pos, new_root) = append(
        elem=2, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 3;

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(3, node3);

    assert new_root = computed_root;

    return ();
}

@external
func test_append_2{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos, new_root) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);
    assert new_pos = 1;

    assert peaks[0] = node1;
    let (new_pos, new_root) = append(
        elem=2, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 3;

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(3, node3);

    assert new_root = computed_root;

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;
    let (new_pos, new_root) = append(
        elem=4, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 4;

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    let (computed_root0) = hash2{hash_ptr=pedersen_ptr}(node3, node4);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(4, computed_root0);

    assert new_root = computed_root;

    return ();
}

@external
func test_append_3{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos, new_root) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);
    assert new_pos = 1;

    assert peaks[0] = node1;
    let (new_pos, new_root) = append(
        elem=2, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 3;

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(3, node3);

    assert new_root = computed_root;

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;
    let (new_pos, new_root) = append(
        elem=4, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 4;

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    let (computed_root0) = hash2{hash_ptr=pedersen_ptr}(node3, node4);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(4, computed_root0);

    assert new_root = computed_root;

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks[1] = node4;

    let (new_pos, new_root) = append(
        elem=5, peaks_len=2, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 7;

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(7, node7);
    assert new_root = computed_root;

    return ();
}

@external
func test_append_4{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos, new_root) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);
    assert new_pos = 1;

    assert peaks[0] = node1;
    let (new_pos, new_root) = append(
        elem=2, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 3;

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(3, node3);

    assert new_root = computed_root;

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;
    let (new_pos, new_root) = append(
        elem=4, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 4;

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    let (computed_root0) = hash2{hash_ptr=pedersen_ptr}(node3, node4);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(4, computed_root0);

    assert new_root = computed_root;

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks[1] = node4;

    let (new_pos, new_root) = append(
        elem=5, peaks_len=2, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 7;

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(7, node7);
    assert new_root = computed_root;

    let (local peaks: felt*) = alloc();

    assert peaks[0] = node7;
    let (new_pos, new_root) = append(
        elem=8, peaks_len=1, peaks=peaks, last_pos=new_pos, last_root=new_root
    );

    assert new_pos = 8;

    let (node8) = hash2{hash_ptr=pedersen_ptr}(8, 8);
    let (computed_root0) = hash2{hash_ptr=pedersen_ptr}(node7, node8);
    let (computed_root) = hash2{hash_ptr=pedersen_ptr}(8, computed_root0);

    assert new_root = computed_root;

    return ();
}
