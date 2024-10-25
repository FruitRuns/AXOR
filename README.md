# AXOR
What is AXOR?
AXOR is an asymmetric encryption algorithm, which is defined as an algorithm where a server can send a public key to a client, the client can encrypt a small amount of data and send this back to the server and only the server can decrypt the message.
# What are AXOR's goals?
AXOR is unique in the way that it does not use complicated mathematics which is generally overwhelming for beginners, the aim of AXOR is not the be the fastest or most light weight algorithm, rather it aims to be the simplest asymmetric algorithm.

The goal of the repository is to provide working code examples of AXOR in different programming languages and to explain the algorithm as efficiently as possible.
# How does AXOR work on a mathematical level?
(Feel free to improve this math communication do be hard)
Imagine a square matrix one side contains random 0's and 1's the other is the identity matrix. Now interate through a 1D matrix of random integers for each integer corresponding to each row of the random 2D matrix do an and gate count the 1's in the bianry output and mod 2 to get a single bit on the identity matrix side and XOR that in, now if we just did this we would be able to figure out the private keys via RREF so to prevent this we get 8 random integers calculate all 256 possible keys and XOR those 8 random integers onto columns this effectively prevents anyone from knowing what the matrix actually is other than the server.

Now give this matrix to someone and tell them to XOR random columns each columns they XOR corresponds to a 1 in the identity matrix which will not overlap with any other 1's telling us which column they XOR'd. Now we find this by trying all possible 256 keys which only we know because we made them up to guess what keys overlayed when they XOR'd which is impossible for an attacker to follow without doing exponentially more calculations than what we are doing (For an attacker this is effectively impossible to do)(We can only do this faster than attackers because it's impossible for them to find out what we XOR'd in because of the special function we used earlier which prevents a case where they could deduce the XOR by looking at which single bit was flipped in the identity matrix), effectively fast guessing the key then we knowing the real matrix can then perform the reversing operation on the real matrix making the values in the identity matrix area contain which lines were XOR'd with no collisions.

## Test (Python)

```bash
if [[ "$(./key_generation.py)" == "5" ]]
then
  echo PASS
else
  echo FAIL;
fi
```

## Test (Rust)

```bash
if [[ "$(cargo run -q)" == "5" ]]
then
  echo PASS
else
  echo FAIL;
fi
```
