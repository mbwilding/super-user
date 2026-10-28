#[macro_export]
macro_rules! wstr {
    ($s:literal) => {{
        const B: &[u8] = $s.as_bytes();
        const A: [u16; B.len() + 1] = {
            let mut a = [0u16; B.len() + 1];
            let mut i = 0;
            while i < B.len() {
                a[i] = B[i] as u16;
                i += 1;
            }
            a
        };
        A
    }};
}

pub fn copy_wide(dst: &mut [u16], src: &[u16]) {
    let n = core::cmp::min(src.len(), dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

pub fn trim_nul(s: &[u16]) -> &[u16] {
    let mut n = 0;
    while n < s.len() && s[n] != 0 {
        n += 1;
    }
    &s[..n]
}

pub fn eq_ignore_case_ascii(wide: &[u16], ascii: &[u8]) -> bool {
    wide.len() == ascii.len()
        && wide
            .iter()
            .zip(ascii)
            .all(|(&w, &a)| w < 0x80 && (w as u8).eq_ignore_ascii_case(&a))
}
