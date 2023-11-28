use std::io::Read;
use std::fs::OpenOptions;

fn main() {
    let mut bs = vec![0; 64 * 1024 * 1024];
    let mut f = OpenOptions::new().read(true).open("/tmp/file").unwrap();
    let mut ts = 0;
    loop {
        let buf = &mut bs[ts..];
        let n = f.read(buf).unwrap();
        let n = n as usize;
        if n == 0 {
            break
        }
        ts += n;
    }

    assert_eq!(ts, 64 * 1024 * 1024);
}
