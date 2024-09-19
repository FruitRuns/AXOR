public_key = [9, 12, 13, 14]
private_key = [12, 14, 14, 9]
pub_priv_out = [0, 0, 0, 0]
for pub_k in range(0, len(public_key)):
    for priv_k in range(0, len(public_key)):
        pub_priv_out[pub_k] += ((public_key[pub_k]&private_key[priv_k]).bit_count()%2)*(2**priv_k)
