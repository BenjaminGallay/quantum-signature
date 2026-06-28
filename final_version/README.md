# Quantum Signature

Alice: the signer. Alice generates private keys, prepares quantum public keys, sends quantum public keys to Bob and Charlie, and sends a classical signed message to Bob.
Bob: the first receiver. Bob verifies Alice's signed message using swap tests. If Bob strongly accepts the message, he forwards the signed message to Charlie.
Charlie: the second receiver. Charlie independently verifies Bob's forwarded signed message using his own quantum public key copies received earlier from Alice.

---

## Files

The main files are:

```text
alice.py
bob.py
charlie.py
simulaqron_network.json
simulaqron_settings.json
```

---

## Protocol Parameters

The main protocol parameters must be the same in Alice, Bob, and Charlie:

```python
SECRET_KEY_LENGTH = 3
FINGERPRINT_QUBITS = SECRET_KEY_LENGTH + 1

MSG_LENGTH = 9
COPIES_PER_KEY = 3
```

Here:

SECRET_KEY_LENGTH = 3 means each secret key is a 3-bit string.
FINGERPRINT_QUBITS = 4 because each Hadamard fingerprint uses three index qubits plus one value qubit.
MSG_LENGTH = 9 means Alice signs a 9-bit classical message.
COPIES_PER_KEY = 3 means each possible bit value has three independent public key copies.

---

## Running the Demo

Open four separate terminals.

```bash
# Terminal 1 -- start the backend
simulaqron start --nodes=Alice,Bob,Charlie --network-config-file simulaqron_network.json --simulaqron-config-file simulaqron_settings.json

# Terminal 2 -- start Charlie first
READOUT_NOISE=0.0 C1=0.15 C2=0.30 python3 charlie.py

# Terminal 3 -- start Bob
READOUT_NOISE=0.0 C1=0.15 C2=0.30 ATTACK_MODE=none python3 bob.py

# Terminal 4 -- start Alice
NOISE=0.0 ALICE_INPUT_BITS=101010101 python3 alice.py
```

---

## Running Attack Tests

The attack mode is controlled by the environment variable ATTACK_MODE.

Available attack modes include:

```text
none
flip_first_bit
flip_all_bits
random_key_only
change_secret_key
```

For example, to simulate an attack where every message bit is flipped and the attacker guesses new secret keys, run Bob with:

```bash
READOUT_NOISE=0.0 C1=0.15 C2=0.30 ATTACK_MODE=flip_all_bits python3 bob.py
```

---

## Thresholds

The verification result is based on the number of failed swap tests.

The verdict is decided as:

```text
fail_count <= C1 * total_tests
    => LEGITIMATE

C1 * total_tests < fail_count < C2 * total_tests
    => AMBIGUOUS

fail_count >= C2 * total_tests
    => ILLEGITIMATE
```

---

## Summary

The demo follows this sequence:

```text
1. Alice generates private keys.
2. Alice sends quantum public keys to Charlie.
3. Alice sends quantum public keys to Bob.
4. Alice sends a classical signed message to Bob.
5. Bob verifies the signed message using swap tests.
6. If Bob strongly accepts, Bob forwards the signed message to Charlie.
7. Charlie independently verifies the transferred signed message.
```

This demonstrates that Bob can pass Alice's signed message to Charlie, and Charlie can verify it using his own quantum public key copies.

## References

The idea behind this implementation stems from this 2001 paper : Gottesman, D., & Chuang, I. (2001). Quantum digital signatures.
