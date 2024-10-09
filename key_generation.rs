use rand::Rng;

// Generates the keys
fn generate_keys() -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let bit_level = 63;

    // client & server have this
    let public_key: Vec<u64> = (0..bit_level)
        .map(|_| rand::thread_rng().gen_range(0..(1u64 << bit_level)))
        .collect();

    // Only server has this
    let private_key: Vec<u64> = (0..bit_level)
        .map(|_| rand::thread_rng().gen_range(0..(1u64 << bit_level)))
        .collect();

    // client & server have this
    let pub_priv_out: Vec<u64> = (0..bit_level)
        .map(|i| {
            (0..bit_level)
                .map(|j| (public_key[i] & private_key[j]).count_ones() as u64 % 2 * (1u64 << j))
                .sum()
        })
        .collect();

    (public_key, private_key, pub_priv_out)
}

fn encrypt(n: u64, public_key: &Vec<u64>, out_key: &Vec<u64>) -> (u64, u64) {
    let mut key_part: u64 = 0;
    let mut data_part: u64 = 0;

    // XOR'ing 11 random ones together should be options^times > 2^n
    // so in this case times is 11 and options is 63
    for _ in 0..11 {
        let enc_mixer = rand::thread_rng().gen_range(0..public_key.len());
        key_part ^= public_key[enc_mixer];
        data_part ^= out_key[enc_mixer];
    }

    // Recommend 2^bit_level limit on n, it'll still work regardless tho
    data_part ^= n;

    (key_part, data_part)
}

fn decrypt(private_key: &Vec<u64>, key: u64, data: u64) -> u64 {
    // Server generates actual out bits for key given to decode data XOR'd in
    let out: u64 = (0..private_key.len())
        .map(|i| ((key & private_key[i]).count_ones() as u64 % 2) * (1u64 << i))
        .sum();

    // Decrypting for the server is as simple as
    data ^ out
}

fn main() {
    let (pub_key, priv_key, out_key) = generate_keys();
    let (key_part, data_part) = encrypt(5, &pub_key, &out_key);
    let output = decrypt(&priv_key, key_part, data_part);
    println!("{}", output); // Should be 5
}
