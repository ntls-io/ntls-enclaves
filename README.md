# Nautilus SGX Service

A monorepo consisting of the Nautilus SGX RPC service as well the enclaves
managed by it. This service manages the instantiation, scheduling, and
dismantling of enclave instances used by the various products and services
offered by Nautilus.  

The [gRPC protocol][grpc] is utilized to expose enclave calls (ECALLs) to the various
Nautilus applications.

[grpc]: https://grpc.io/
