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
func test_append_1{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (last_pos) = get_last_pos();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (last_pos) = get_last_pos();
    assert last_pos = 3;

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (root) = get_root();
    assert root = node3;

    return ();
}

@external
func test_append_2{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks1: felt*) = alloc();

    let (last_pos) = get_last_pos();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks1);

    assert peaks1[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks1);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks2: felt*) = alloc();

    assert peaks2[0] = node3;
    append(elem=4, peaks_len=1, peaks=peaks2);

    let (last_pos) = get_last_pos();
    assert last_pos = 4;

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    let (root_hash) = hash2{hash_ptr=pedersen_ptr}(node3, node4);

    let (root) = get_root();
    assert root = root_hash;

    return ();
}

@external
func test_append_3{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks1: felt*) = alloc();

    let (last_pos) = get_last_pos();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks1);

    assert peaks1[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks1);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks2: felt*) = alloc();

    assert peaks2[0] = node3;
    append(elem=4, peaks_len=1, peaks=peaks2);

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks2[1] = node4;

    append(elem=5, peaks_len=2, peaks=peaks2);

    let (last_pos) = get_last_pos();
    assert last_pos = 7;

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (root) = get_root();
    assert root = node7;

    return ();
}

@external
func test_append_4{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks1: felt*) = alloc();

    let (last_pos) = get_last_pos();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks1);

    assert peaks1[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks1);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks2: felt*) = alloc();

    assert peaks2[0] = node3;
    append(elem=4, peaks_len=1, peaks=peaks2);

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks2[1] = node4;

    append(elem=5, peaks_len=2, peaks=peaks2);

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (local peaks3: felt*) = alloc();

    assert peaks3[0] = node7;
    append(elem=8, peaks_len=1, peaks=peaks3);

    let (last_pos) = get_last_pos();
    assert last_pos = 8;

    let (node8) = hash2{hash_ptr=pedersen_ptr}(8, 8);
    let (root_hash) = hash2{hash_ptr=pedersen_ptr}(node7, node8);

    let (root) = get_root();
    assert root = root_hash;

    return ();
}
