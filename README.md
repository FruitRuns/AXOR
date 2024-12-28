# AXOR
What is AXOR?
AXOR is an asymmetric encryption algorithm, which is defined as an algorithm where a server can send a public key to a client, the client can encrypt a small amount of data and send this back to the server and only the server can decrypt the message.
# What are AXOR's goals?
AXOR is unique in the way that it does not use complicated mathematics which is generally overwhelming for beginners, the aim of AXOR is not the be the fastest or most light weight algorithm, rather it aims to be the simplest asymmetric algorithm.

The goal of the repository is to provide working code examples of AXOR in different programming languages and to explain the algorithm as efficiently as possible.
# How does AXOR work on a mathematical level?
Logic gate magic

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
