const w: u32 = 32;
const r: usize = 12;
const b: usize = 16;
const c: usize = 4;
const t: usize = 26;

const P: u32= 0xb7e15163;  // magic word
const Q: u32 = 0x9e3779b9;

fn ROTL(x: u32, y: u32) -> u32 {
    // ((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1))))
    let (temp1, ..) = x.overflowing_shl(y&(w-1));
    let (temp2, ..) = x.overflowing_shr(w-(y&(w-1)));
    temp1 | temp2
}

fn ROTR(x: u32, y: u32) -> u32 {
    // ((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1))))
    let (temp1, ..) = x.overflowing_shr(y&(w-1));
    let (temp2, ..) = x.overflowing_shl(w-(y&(w-1)));
    temp1 | temp2
}

fn setup(K: Vec<u8>) -> Vec<u32> {
    let (mut i, mut j, mut k, mut A, mut B, u) = (b, 0usize, 0usize, 0u32, 0u32, 4usize);
    let mut L: [u32; c] = [0; c];
    
    L[c - 1] = 0;
    while i > 0 {
        i -= 1;
        L[i / u] = (L[i / u] << 8) + u32::from(K[i]);
    }

    let mut S = [0u32; t];
    S[0] = P;
    i = 1;
    while i < t {
        // S[i] = S[i - 1] + Q;
        let temp: u32 = S[i - 1];
        S[i] = temp.wrapping_add(Q);
        i += 1;
    }

    i =  0;
    while k < 3 * t {
        // S[i] = ROTL(S[i] + (A + B), 3);
        let mut temp: u32 = A;
        temp = temp.wrapping_add(B);
        temp = temp.wrapping_add(S[i]);
        S[i] = ROTL(temp, 3);
        A = S[i];
        // L[j] = ROTL(L[j] + (A + B), (A + B));
        temp = A;
        let temp1 = temp.wrapping_add(B);
        temp = temp1.wrapping_add(L[j]);
        L[j] = ROTL(temp, temp1);
        B = L[j];

        i = (i + 1) % t;
        j = (j + 1) % c;
        k += 1;
    }
    return S.to_vec();
}

fn getWords(text: Vec<u8>) -> (u32, u32) {
    let mut word1: u32 = 0;
    let mut word2: u32 = 0;
    
    let (pt1, pt2) = text.split_at(4);
    let mut i = 0;
    for val in pt1 {
		let val1 = u32::from(*val);
        word1 = word1 + (val1 << 8 * i);
        i += 1;
    }

    i = 0;
    for val in pt2 {
		let val1 = u32::from(*val);
        word2 = word2 + (val1 << 8 * i);
        i += 1;
    }
    (word1, word2)
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    let (word1, word2) = getWords(plaintext);    // Convert plaintext to two words
    
    let S = setup(key);

    let mut A = word1.wrapping_add(S[0]);
    let mut B = word2.wrapping_add(S[1]);
    
    let mut i = 1;
    while i <= r {
        A = ROTL(A ^ B, B).wrapping_add(S[2 * i]);
        B = ROTL(B ^ A, A).wrapping_add(S[2 * i + 1]);
        i += 1;
    }
    let ct1: [u8; 4] = A.to_be_bytes();
    let ct2: [u8; 4] = B.to_be_bytes();

	let mut ciphertext = Vec::new();
    let mut i: usize = 4;
    while i > 0 {
        ciphertext.push(ct1[i-1]);
        i -= 1;
    }
    let mut i: usize = 4;
    while i > 0 {
        ciphertext.push(ct2[i-1]);
        i -= 1;
    }
	ciphertext
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let (word1, word2) = getWords(ciphertext); // Convert ciphertext to two words
    let S = setup(key);

    let mut A = word1;
    let mut B = word2;
    
    let mut i = r;
    while i > 0 {
        B = ROTR(B.wrapping_sub(S[2 * i + 1]), A) ^ A;
        A = ROTR(A.wrapping_sub(S[2 * i]), B) ^ B;
        i -= 1;
    }
    B = B.wrapping_sub(S[1]);
    A = A.wrapping_sub(S[0]);
    let pt1: [u8; 4] = A.to_be_bytes();
    let pt2: [u8; 4] = B.to_be_bytes();

	let mut plaintext = Vec::new();
    let mut i: usize = 4;
    while i > 0 {
        plaintext.push(pt1[i-1]);
        i -= 1;
    }
    let mut i: usize = 4;
    while i > 0 {
        plaintext.push(pt2[i-1]);
        i -= 1;
    }
	plaintext
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn encode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
    	let res = encode(key, pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
    	let res = encode(key, pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
    	let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let res = decode(key, ct);
    	assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
    	let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let res = decode(key, ct);
    	assert!(&pt[..] == &res[..]);
    }
}
