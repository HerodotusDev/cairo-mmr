%lang starknet
from src.mmr import verify_proof, append, update
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.hash import hash2

@external 
func test_update{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
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

    let (node1_new) = hash2{hash_ptr=pedersen_ptr}(1, 420);
    let (node3_1_new) = hash2{hash_ptr=pedersen_ptr}(node1_new, node2);
    let (node3_new) = hash2{hash_ptr=pedersen_ptr}(3, node3_1_new);
    let (node7_1_new) = hash2{hash_ptr=pedersen_ptr}(node3_new, node6);
    let (node7_new) = hash2{hash_ptr=pedersen_ptr}(7, node7_1_new);

    update(1, 1, 420, 2, proof, 2, peaks);

    let (local peaks_new: felt*) = alloc();
    assert peaks_new[0] = node7_new;
    assert peaks_new[1] = node8;

    verify_proof(1, 420, 2, proof, 2, peaks_new);

    return ();
}
