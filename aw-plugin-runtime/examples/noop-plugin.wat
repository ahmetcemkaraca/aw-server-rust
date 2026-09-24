(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    i32.const 1024)
  (func (export "invoke") (param i32 i32) (result i64)
    i64.const 390842023936)
  (data (i32.const 0)
    "{\"schema_version\":1,\"ui\":[],\"writes\":[],\"network\":[],\"ai\":[],\"storage\":[],\"destructive\":[]}")
)
