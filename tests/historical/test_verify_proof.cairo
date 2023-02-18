%lang starknet
from src.historical_mmr import append, verify_past_proof, verify_proof
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.hash import hash2

@external
func test_verify_proof_1_leaf{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;

    let (local proof: felt*) = alloc();
    verify_proof(1, 1, 0, proof, 1, peaks);

    return ();
}

@external
func test_verify_past_proof_1_leaf{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    ) {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (cur_pos: felt) = append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;

    let (local proof: felt*) = alloc();
    verify_past_proof(1, 1, 0, proof, 1, peaks, cur_pos);

    return ();
}

@external
func test_verify_past_proof_2_leaves{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (cur_pos: felt) = append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;

    let (local proof: felt*) = alloc();
    verify_past_proof(1, 1, 0, proof, 1, peaks, cur_pos);

    let (cur_pos_2: felt) = append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;

    verify_past_proof(2, 2, 1, proof, 1, peaks, cur_pos_2);
    return ();
}

@external
func test_verify_proof_2_leaves{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node2;
    verify_proof(1, 1, 1, proof, 1, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    verify_proof(2, 2, 1, proof, 1, peaks);

    return ();
}

@external
func test_verify_past_proof_3_leaves{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (local peaks_1: felt*) = alloc();
    let (last_pos_leaf_1) = append(elem=1, peaks_len=0, peaks=peaks_1);
    let (local proof_1: felt*) = alloc();
    assert peaks_1[0] = node1;

    let (local proof_2: felt*) = alloc();
    assert proof_2[0] = node1;
    let (last_pos_leaf_2) = append(elem=2, peaks_len=1, peaks=peaks_1);
    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (local peaks_2: felt*) = alloc();
    assert peaks_2[0] = node3;

    let (last_pos_leaf_3) = append(elem=4, peaks_len=1, peaks=peaks_2);
    let (local proof_3: felt*) = alloc();
    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks_2[1] = node4;

    verify_past_proof(4, 4, 0, proof_3, 2, peaks_2, last_pos_leaf_3);
    verify_past_proof(1, 1, 0, proof_1, 1, peaks_1, last_pos_leaf_1);
    verify_past_proof(2, 2, 1, proof_2, 1, peaks_2, last_pos_leaf_2);
    return ();
}

@external
func test_verify_proof_3_leaves{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;
    append(elem=4, peaks_len=1, peaks=peaks);

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks[1] = node4;

    let (local proof: felt*) = alloc();
    assert proof[0] = node2;
    verify_proof(1, 1, 1, proof, 2, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    verify_proof(2, 2, 1, proof, 2, peaks);

    let (local proof: felt*) = alloc();
    verify_proof(4, 4, 0, proof, 2, peaks);

    return ();
}

@external
func test_verify_past_proof_4_leaves{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (local peaks_1: felt*) = alloc();
    let (last_pos_leaf_1) = append(elem=1, peaks_len=0, peaks=peaks_1);
    let (local proof_1: felt*) = alloc();
    assert peaks_1[0] = node1;
    verify_past_proof(1, 1, 0, proof_1, 1, peaks_1, last_pos_leaf_1);

    let (local proof_2: felt*) = alloc();
    assert proof_2[0] = node1;
    let (last_pos_leaf_2) = append(elem=2, peaks_len=1, peaks=peaks_1);
    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (local peaks_2: felt*) = alloc();
    assert peaks_2[0] = node3;
    verify_past_proof(2, 2, 1, proof_2, 1, peaks_2, last_pos_leaf_2);

    let (last_pos_leaf_3) = append(elem=4, peaks_len=1, peaks=peaks_2);
    let (local proof_3: felt*) = alloc();
    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks_2[1] = node4;
    verify_past_proof(4, 4, 0, proof_3, 2, peaks_2, last_pos_leaf_3);

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (last_pos_leaf_4) = append(elem=5, peaks_len=2, peaks=peaks_2);

    let (local peaks_3: felt*) = alloc();
    assert peaks_3[0] = node7;
    let (local proof_4: felt*) = alloc();
    assert proof_4[0] = node4;
    assert proof_4[1] = node3;
    verify_past_proof(5, 5, 2, proof_4, 1, peaks_3, last_pos_leaf_4);
    return ();
}

@external
func test_verify_proof_4_leaves{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;
    append(elem=4, peaks_len=1, peaks=peaks);

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks[1] = node4;
    append(elem=5, peaks_len=2, peaks=peaks);

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node7;

    let (local proof: felt*) = alloc();
    assert proof[0] = node2;
    assert proof[1] = node6;
    verify_proof(1, 1, 2, proof, 1, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    assert proof[1] = node6;
    verify_proof(2, 2, 2, proof, 1, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node5;
    assert proof[1] = node3;
    verify_proof(4, 4, 2, proof, 1, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node4;
    assert proof[1] = node3;
    verify_proof(5, 5, 2, proof, 1, peaks);

    return ();
}

@external
func test_verify_past_proof_5_leaves{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;
    let (local peaks: felt*) = alloc();
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (local peaks_1: felt*) = alloc();
    let (last_pos_leaf_1) = append(elem=1, peaks_len=0, peaks=peaks_1);
    let (local proof_1: felt*) = alloc();
    assert peaks_1[0] = node1;

    let (local proof_2: felt*) = alloc();
    assert proof_2[0] = node1;
    let (last_pos_leaf_2) = append(elem=2, peaks_len=1, peaks=peaks_1);
    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (local peaks_2: felt*) = alloc();
    assert peaks_2[0] = node3;

    let (last_pos_leaf_3) = append(elem=4, peaks_len=1, peaks=peaks_2);
    let (local proof_3: felt*) = alloc();
    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks_2[1] = node4;

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (last_pos_leaf_4) = append(elem=5, peaks_len=2, peaks=peaks_2);
    let (local peaks_3: felt*) = alloc();
    assert peaks_3[0] = node7;
    let (local proof_4: felt*) = alloc();
    assert proof_4[0] = node4;
    assert proof_4[1] = node3;

    let (last_pos_leaf_5) = append(elem=8, peaks_len=1, peaks=peaks_3);
    let (local proof_5: felt*) = alloc();
    let (local peaks_4: felt*) = alloc();
    assert peaks_4[0] = node7;
    let (node8) = hash2{hash_ptr=pedersen_ptr}(8, 8);
    assert peaks_4[1] = node8;

    verify_past_proof(8, 8, 0, proof_5, 2, peaks_4, last_pos_leaf_5);
    verify_past_proof(2, 2, 1, proof_2, 1, peaks_2, last_pos_leaf_2);
    verify_past_proof(1, 1, 0, proof_1, 1, peaks_1, last_pos_leaf_1);
    verify_past_proof(4, 4, 0, proof_3, 2, peaks_2, last_pos_leaf_3);
    verify_past_proof(5, 5, 2, proof_4, 1, peaks_3, last_pos_leaf_4);
    return ();
}

@external
func test_verify_proof_5_leaves{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;
    append(elem=4, peaks_len=1, peaks=peaks);

    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks[1] = node4;
    append(elem=5, peaks_len=2, peaks=peaks);

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node7;
    append(elem=8, peaks_len=1, peaks=peaks);

    let (node8) = hash2{hash_ptr=pedersen_ptr}(8, 8);
    assert peaks[1] = node8;

    let (local proof: felt*) = alloc();
    assert proof[0] = node2;
    assert proof[1] = node6;
    verify_proof(1, 1, 2, proof, 2, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    assert proof[1] = node6;
    verify_proof(2, 2, 2, proof, 2, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node5;
    assert proof[1] = node3;
    verify_proof(4, 4, 2, proof, 2, peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node4;
    assert proof[1] = node3;
    verify_proof(5, 5, 2, proof, 2, peaks);

    let (local proof: felt*) = alloc();
    verify_proof(8, 8, 0, proof, 2, peaks);

    return ();
}

@external
func test_verify_proof_invalid_index{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    %{ expect_revert() %}
    verify_proof(2, 2, 1, proof, 1, peaks);

    return ();
}

@external
func test_verify_proof_invalid_peaks{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node1;

    let (local proof: felt*) = alloc();
    assert proof[0] = node2;
    %{ expect_revert() %}
    verify_proof(1, 1, 1, proof, 1, peaks);

    return ();
}

@external
func test_verify_proof_invalid_proof{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    append(elem=1, peaks_len=0, peaks=peaks);

    assert peaks[0] = node1;
    append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    %{ expect_revert() %}
    verify_proof(1, 1, 1, proof, 1, peaks);

    return ();
}
