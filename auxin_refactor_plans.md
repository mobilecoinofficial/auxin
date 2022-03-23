The absolute most critical change we need to make is to generalize over common Signal web API request types (i.e. uploading to CDN, downloading from CDN, signal service requests). The amount of copy-paste gunk this will clear out will probably result in the refactored Auxin being much, much smaller than its current incarnation, even if we're adding features.

Generally speaking the Auxin refactor can have a much lower LoC if we do it right. 

* Have an explicit ***ServiceConfiguration*** type, as an enum. Separate (not-tightly-coupled) functions like `get_service_address(&service_configuration) -> &str {...}` - these would not be methods, rather, free-floating functions, so you can define more of them without changing the `ServiceConfiguration`'s type signature. 
* Replace the `protobuf-codegen-pure` and `protobuf` crates with `Prost` to be consistent with the rest of the Signal ecosystem. 
* * While I'm on the subject of protocol buffers, the hacky but pervasive `fix_protobuf_buf()` has got to go. 
* Store different sessions for different peers separately (for direct messages - groups might not permit this)
* No AuxinApp as defined by the "auxin" crate proper. Instead, you have much less-tightly-coupled parts (one AuxinSession per peer, perhaps) and in crates that implement the i/o required to make a full Auxin app like auxin-cli (and a hypothetical auxin-wasm) we can put these parts together - since the implementation crates know what context they will be executed in, that frees us up to use things like thread-locals and mutexes. This permits much nicer (and less-hacky) concurrency.
* Separate steps for receiving and decrypting a message- `EncryptedMessage` struct.
* Eliminate `MessageIn` and `MessageOut`, as they are just the `Content` protocol buffer struct with a few of its fields duplicated. This seemed necessary before I fully understood the problem space, but now they just seem pointless. 
* Get rid of `customerror` completely. Replace with either `thiserror` (looks promising) or just plain Rust enums.
* Statefulness primitives should include functionality for caching attachments and other large blobs, either directly or by exposing some kind of hooks (jsonrpc?).
* Better support for unit testing in the way the networking works (i.e. a context where you can send fake http requests that don't do actual i/o).
* The "auxin" sub-crate should be renamed to "auxin-core" to avoid ambiguity.