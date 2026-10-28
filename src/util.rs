pub fn copy_str(dst: &mut [u16], s: &str) {
    let mut i = 0;
    for u in s.encode_utf16() {
        if i + 1 >= dst.len() {
            break;
        }
        dst[i] = u;
        i += 1;
    }
    dst[i] = 0;
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
