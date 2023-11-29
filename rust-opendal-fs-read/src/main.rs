use std::io::Read;
use opendal::services::Fs;
use opendal::Operator;

fn main() {
    let mut cfg = Fs::default();
    cfg.root("/tmp");
    let op = Operator::new(cfg).unwrap().finish().blocking();

    let mut bs = vec![0; 64 * 1024 * 1024];

    let mut f = op.reader("file").unwrap();
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
