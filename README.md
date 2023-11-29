# When I find rust is slow

It's crazy, I found a case where Rust is slower than Python! But, really?

## Setup

Reproduce the same result requires:

- Rust Development Tools (cargo, rustc, ..)
- Python Development Tools (python3, venv)
- hyperfine (benchmark runner)
- CPU (one of `AMD Ryzen 9 5950X`, `AMD R7 5700X`, `AMD Ryzen 9 5900X`)

## Quick Start

```shell
./bench python-fs-read rust-std-fs-read
```

For example:

```shell
:) `./bench python-fs-read rust-std-fs-read`
    Finished release [optimized] target(s) in 0.00s
Benchmark 1: python-fs-read/test.py
  Time (mean ± σ):      22.6 ms ±   1.5 ms    [User: 8.0 ms, System: 14.4 ms]
  Range (min … max):    21.1 ms …  30.1 ms    115 runs
 
Benchmark 2: rust-std-fs-read/target/release/test
  Time (mean ± σ):      26.2 ms ±   1.4 ms    [User: 0.3 ms, System: 26.1 ms]
  Range (min … max):    25.4 ms …  36.2 ms    107 runs
```

If python has lower `System` time than rust, you reproduce the same result.
