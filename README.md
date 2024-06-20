# Shellcoder: Write shellcode payloads in a flash!


_minimum supported Rust version_: **1.61.0**


_Documentation_: [docs.rs/shellcoder](https://docs.rs/shellcoder).


## Feature flags


`shellcoder` comes with the following feature flags:

| name    | description                                                                                   | enabled by default |
|---------|-----------------------------------------------------------------------------------------------|--------------------|
| `std`   | Use the standard library. Gives access to I/O backed and `Vec` backed implementations.        | `no`               |


## Add `shellcoder` to your library


To add `shellcoder` to your Rust library, you can use [Cargo]:

```shell
$ cargo add shellcoder
```

Or alternatively, edit your [`Cargo.toml`](https://doc.rust-lang.org/cargo/reference/manifest.html#the-description-field)
and add the following line under the [`dependencies`](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
section:

```yaml
shellcoder = "0.1.0"
```


## Examples


The following code writes a simple shellcode that comprises two addresses
separated by a 8-byte gap. It uses the static implementation, i.e. no dynamic
memory allocation is performed.


```rust
use shellcoder::{
    Op as _,
    Shellcoder as _,
};
use shellcoder::r#static::Shellcoder;
use shellcoder::Result;

pub fn main() -> Result<()> {
  // We define a scratch buffer to be used by [`Shellcoder`].
  let mut scratch_buffer = [0u8; 0x18];

  // We instantiate a _shellcoder_, the _static_ one.
  let mut shellcoder = Shellcoder::new(&mut scratch_buffer);

  // We build the shellcode.
  let shellcode = shellcoder
    .write_le(0x10000abccu64)? // writes little-endian encoded 0x10000abcc.
    .fill(8, b'A')?            // moves the cursor 8 bytes ahead,
                               // filling the gap with 'A'
    .write_le(0x10000fffc)?    // writes little-endian encoded 0x10000fffc.
    .get();

  assert_eq!(shellcode, &[
    0xcc, 0xab, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0xfc, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  ]);
  Ok(())
}
```


## License


Apache2, see [License](LICENSE).


[Cargo]: https://doc.rust-lang.org/cargo/
