# cairo-mmr
An implementation of Merkle Mountain Ranges in cairo, using Pedersen hash. 
This library should be used alongside an off-chain implmentation, keeping track of all the node hashes, to generate the proofs and compute the peaks

## Set Up
You should have [Protostar](https://docs.swmansion.com/protostar/) installed. See [installation](https://docs.swmansion.com/protostar/docs/tutorials/installation) docs.

### Project initialization
```bash
protostar init <your-project-name>
cd <your-project-name>
```

### Installing the library
```bash
protostar install HerodotusDev/cairo-mmr
```

## Usage
```cairo
// src/main.cairo

%lang starknet
from cairo_mmr.src.mmr import append, verify_proof
```

For demonstration purposes, in the next example we are going to keep track of the hashes and peaks on-chain. An off-chain solution should be used instead


```cairo
func demo{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    let (local peaks: felt*) = alloc();
    
    append(elem=1, peaks_len=0, peaks=peaks);

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, 1);
    assert peaks[0] = node1;
    
    append(elem=2, peaks_len=1, peaks=peaks);

    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, 2);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);

    let (local peaks: felt*) = alloc();
    assert peaks[0] = node3;

    let (local proof: felt*) = alloc();
    assert proof[0] = node2;
    verify_proof(index=1, value=1, proof_len=1, proof=proof, peaks_len=1, peaks=peaks);

    let (local proof: felt*) = alloc();
    assert proof[0] = node1;
    verify_proof(index=2, value=2, proof_len=1, proof=proof, peaks_len=1, peaks=peaks);

    return ();
}
```

## Development

### Project set up
```bash
git clone git@github.com:HerodotusDev/cairo-mmr.git
cd cairo-mmr
```

### Compile
```bash
protostar build
```

### Test
```bash
protostar test tests/
```

## License
[GNU GPLv3](https://github.com/HerodotusDev/cairo-mmr/blob/main/LICENSE)
