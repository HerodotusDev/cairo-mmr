%lang starknet
from src.stateless_mmr import append, verify_proof
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.hash import hash2

@external
func test_verify_proof_1_leaf{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos, new_root) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);

    assert peaks[0] = node1;

    let (local proof: felt*) = alloc();
    verify_proof(1, 1, 0, proof, 1, peaks, new_pos, new_root);

    return ();
}

@external
func test_verify_proof_2_leaves{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos1, new_root1) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);

    assert peaks[0] = node1;

    let (local proof: felt*) = alloc();
    verify_proof(1, 1, 0, proof, 1, peaks, new_pos1, new_root1);

    let (new_pos2, new_root2) = append(
        elem=2, peaks_len=1, peaks=peaks, last_pos=new_pos1, last_root=new_root1
    );

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;

    verify_proof(2, 2, 1, proof, 1, peaks, new_pos2, new_root2);
    return ();
}

@external
func test_verify_proof_3_leaves{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (local peaks_1: felt*) = alloc();
    let (new_pos1, new_root1) = append(elem=1, peaks_len=0, peaks=peaks_1, last_pos=0, last_root=0);

    let (local proof_1: felt*) = alloc();
    assert peaks_1[0] = node1;

    let (local proof_2: felt*) = alloc();
    assert proof_2[0] = node1;
    let (new_pos2, new_root2) = append(
        elem=2, peaks_len=1, peaks=peaks_1, last_pos=new_pos1, last_root=new_root1
    );
    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (local peaks_2: felt*) = alloc();
    assert peaks_2[0] = node3;

    let (new_pos3, new_root3) = append(
        elem=4, peaks_len=1, peaks=peaks_2, last_pos=new_pos2, last_root=new_root2
    );
    let (local proof_3: felt*) = alloc();
    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks_2[1] = node4;

    verify_proof(4, 4, 0, proof_3, 2, peaks_2, new_pos3, new_root3);
    verify_proof(1, 1, 0, proof_1, 1, peaks_1, new_pos1, new_root1);
    verify_proof(2, 2, 1, proof_2, 1, peaks_2, new_pos2, new_root2);

    return ();
}

@external
func test_verify_proof_4_leaves{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (local peaks_1: felt*) = alloc();
    let (new_pos1, new_root1) = append(elem=1, peaks_len=0, peaks=peaks_1, last_pos=0, last_root=0);

    let (local proof_1: felt*) = alloc();
    assert peaks_1[0] = node1;
    verify_proof(1, 1, 0, proof_1, 1, peaks_1, new_pos1, new_root1);

    let (local proof_2: felt*) = alloc();
    assert proof_2[0] = node1;
    let (new_pos2, new_root2) = append(
        elem=2, peaks_len=1, peaks=peaks_1, last_pos=new_pos1, last_root=new_root1
    );
    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (local peaks_2: felt*) = alloc();
    assert peaks_2[0] = node3;
    verify_proof(2, 2, 1, proof_2, 1, peaks_2, new_pos2, new_root2);

    let (new_pos3, new_root3) = append(
        elem=4, peaks_len=1, peaks=peaks_2, last_pos=new_pos2, last_root=new_root2
    );
    let (local proof_3: felt*) = alloc();
    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks_2[1] = node4;
    verify_proof(4, 4, 0, proof_3, 2, peaks_2, new_pos3, new_root3);

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (new_pos4, new_root4) = append(
        elem=5, peaks_len=2, peaks=peaks_2, last_pos=new_pos3, last_root=new_root3
    );

    let (local peaks_3: felt*) = alloc();
    assert peaks_3[0] = node7;
    let (local proof_4: felt*) = alloc();
    assert proof_4[0] = node4;
    assert proof_4[1] = node3;
    verify_proof(5, 5, 2, proof_4, 1, peaks_3, new_pos4, new_root4);
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
    let (new_pos1, new_root1) = append(elem=1, peaks_len=0, peaks=peaks_1, last_pos=0, last_root=0);
    let (local proof_1: felt*) = alloc();
    assert peaks_1[0] = node1;

    let (local proof_2: felt*) = alloc();
    assert proof_2[0] = node1;
    let (new_pos2, new_root2) = append(
        elem=2, peaks_len=1, peaks=peaks_1, last_pos=new_pos1, last_root=new_root1
    );
    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    let (local peaks_2: felt*) = alloc();
    assert peaks_2[0] = node3;

    let (new_pos3, new_root3) = append(
        elem=4, peaks_len=1, peaks=peaks_2, last_pos=new_pos2, last_root=new_root2
    );

    let (local proof_3: felt*) = alloc();
    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, 4);
    assert peaks_2[1] = node4;

    let (node5) = hash2{hash_ptr=pedersen_ptr}(5, 5);
    let (node6_1) = hash2{hash_ptr=pedersen_ptr}(node4, node5);
    let (node6) = hash2{hash_ptr=pedersen_ptr}(6, node6_1);
    let (node7_1) = hash2{hash_ptr=pedersen_ptr}(node3, node6);
    let (node7) = hash2{hash_ptr=pedersen_ptr}(7, node7_1);

    let (new_pos4, new_root4) = append(
        elem=5, peaks_len=2, peaks=peaks_2, last_pos=new_pos3, last_root=new_root3
    );
    let (local peaks_3: felt*) = alloc();
    assert peaks_3[0] = node7;
    let (local proof_4: felt*) = alloc();
    assert proof_4[0] = node4;
    assert proof_4[1] = node3;

    let (new_pos5, new_root5) = append(
        elem=8, peaks_len=1, peaks=peaks_3, last_pos=new_pos4, last_root=new_root4
    );
    let (local proof_5: felt*) = alloc();
    let (local peaks_4: felt*) = alloc();
    assert peaks_4[0] = node7;
    let (node8) = hash2{hash_ptr=pedersen_ptr}(8, 8);
    assert peaks_4[1] = node8;

    verify_proof(8, 8, 0, proof_5, 2, peaks_4, new_pos5, new_root5);
    verify_proof(2, 2, 1, proof_2, 1, peaks_2, new_pos2, new_root2);
    verify_proof(1, 1, 0, proof_1, 1, peaks_1, new_pos1, new_root1);
    verify_proof(4, 4, 0, proof_3, 2, peaks_2, new_pos3, new_root3);
    verify_proof(5, 5, 2, proof_4, 1, peaks_3, new_pos4, new_root4);
    return ();
}

@external
func test_verify_proof_invalid_index{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos, new_root) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    %{ expect_revert() %}
    verify_proof(2, 2, 1, proof, 1, peaks, new_pos, new_root);

    return ();
}

@external
func test_verify_proof_invalid_peaks{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos1, new_root1) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);

    assert peaks[0] = node1;
    let (new_pos2, new_root2) = append(
        elem=2, peaks_len=1, peaks=peaks, last_pos=new_pos1, last_root=new_root1
    );

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node1;

    let (local proof: felt*) = alloc();
    assert proof[0] = node2;
    %{ expect_revert() %}
    verify_proof(1, 1, 1, proof, 1, peaks, new_pos2, new_root2);
    %{ expect_revert() %}
    verify_proof(1, 1, 1, proof, 1, peaks, new_pos1, new_root1);

    return ();
}

@external
func test_verify_proof_invalid_proof{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    let (new_pos1, new_root1) = append(elem=1, peaks_len=0, peaks=peaks, last_pos=0, last_root=0);

    assert peaks[0] = node1;
    let (new_pos2, new_root2) = append(
        elem=2, peaks_len=1, peaks=peaks, last_pos=new_pos1, last_root=new_root1
    );

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    %{ expect_revert() %}
    verify_proof(1, 1, 1, proof, 1, peaks, new_pos1, new_root1);
    %{ expect_revert() %}
    verify_proof(1, 1, 1, proof, 1, peaks, new_pos2, new_root2);

    return ();
}
