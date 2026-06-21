import asyncio
import os
import random
import sys
from asyncio import StreamReader, StreamWriter
from pathlib import Path

from netqasm.runtime.settings import set_simulator

set_simulator("simulaqron")

from netqasm.sdk import EPRSocket, Qubit  
from netqasm.sdk.external import NetQASMConnection  
from simulaqron.general.host_config import SocketsConfig
from simulaqron.sdk.protocol import SimulaQronClassicalClient
from simulaqron.settings import network_config, simulaqron_settings
from simulaqron.settings.network_config import NodeConfigType

# ── States ────────────────────────────────────────────────────────────────────

STATE_WAITING_HI = "WAITING_HI"
STATE_SENDING_PUBLIC_KEY = "SENDING_PUBLIC_KEY"
STATE_WAITING_FOR_INPUT = "WAITING_FOR_INPUT"
STATE_DONE = "DONE"


# ── Constants ─────────────────────────────────────────────────────────────────

SECRET_KEY_LENGTH = 3
FINGERPRINT_QUBITS = SECRET_KEY_LENGTH + 1

#Change here, Max is (L=9, M=3) (L=28, M=1)
MSG_LENGTH = 9
COPIES_PER_KEY = 3 #M

PUBLIC_KEY_QUBITS = FINGERPRINT_QUBITS * MSG_LENGTH * 2 * COPIES_PER_KEY
BATCH_PUBLIC_KEY_QUBITS = FINGERPRINT_QUBITS * 2 * COPIES_PER_KEY
CORRECTION_BITS = 2 * PUBLIC_KEY_QUBITS
SIGNED_BLOCK_LENGTH = 1 + COPIES_PER_KEY * SECRET_KEY_LENGTH

INPUT_ENV_VAR = "ALICE_INPUT_BITS"

# NOISE denotes the probability that each individual qubit in the EPR pair is flipped
NOISE = float(os.environ.get("NOISE", "0.0"))
PRIVATE_KEY = None


# ── Event Loop ────────────────────────────────────────────────────────────────

def apply_noise(qubit: Qubit) -> None:
    """Flips the qubit with a probability of p(NOISE)"""
    if NOISE <= 0.0:
        return
    
    r = random.random()
    if r < NOISE:
        qubit.X()

def random_bits(n: int) -> str:
    return "".join(str(random.randint(0, 1)) for _ in range(n))


def choose_private_key() -> list[tuple[list[str], list[str]]]:
    private_key = []

    for _ in range(MSG_LENGTH):
        candidates = [
            format(value, f"0{SECRET_KEY_LENGTH}b")
            for value in range(2**SECRET_KEY_LENGTH)
        ]
        random.shuffle(candidates)

        keys0 = candidates[:COPIES_PER_KEY]
        keys1 = candidates[COPIES_PER_KEY : 2 * COPIES_PER_KEY]

        private_key.append((keys0, keys1))

    return private_key


def prepare_hadamard_fingerprint(conn: NetQASMConnection, bits: str) -> list[Qubit]:
    """Prepare 1/sqrt(2^n) sum_c |c>|bits . c mod 2>."""
    if len(bits) != SECRET_KEY_LENGTH or any(bit not in "01" for bit in bits):
        raise ValueError(
            f"Hadamard fingerprint input must be a {SECRET_KEY_LENGTH}-bit string"
        )

    qubits = [Qubit(conn) for _ in range(FINGERPRINT_QUBITS)]
    index_qubits = qubits[:SECRET_KEY_LENGTH]
    value_qubit = qubits[SECRET_KEY_LENGTH]

    for index_qubit in index_qubits:
        index_qubit.H()

    for j, bit in enumerate(bits):
        if bit == "1":
            index_qubits[j].cnot(value_qubit)

    return qubits


def create_public_key_for_index(private_key, index: int, conn):
    fingerprints0 = []
    fingerprints1 = []

    for m in range(COPIES_PER_KEY):
        key0 = private_key[index][0][m]
        key1 = private_key[index][1][m]

        fingerprints0.append(prepare_hadamard_fingerprint(conn, key0))
        fingerprints1.append(prepare_hadamard_fingerprint(conn, key1))

    return fingerprints0, fingerprints1


def teleport_public_key_batch(public_key_batch, epr_qubits, conn) -> str:
    corrections = ""

    for j in range(2):
        for m in range(COPIES_PER_KEY):
            for k in range(FINGERPRINT_QUBITS):
                index = (j * COPIES_PER_KEY + m) * FINGERPRINT_QUBITS + k

                apply_noise(epr_qubits[index])

                public_key_batch[j][m][k].cnot(epr_qubits[index])
                public_key_batch[j][m][k].H()

                q_measure = public_key_batch[j][m][k].measure()
                epr_measure = epr_qubits[index].measure()

                conn.flush()

                corrections += str(int(q_measure))
                corrections += str(int(epr_measure))

    return corrections

def send_public_keys_to_receiver(private_key, epr_socket, conn, writer, receiver_name: str) -> None:
    corrections = ""

    for i in range(MSG_LENGTH):
        public_key_batch = create_public_key_for_index(private_key, i, conn)

        epr_qubits = epr_socket.create_keep(number=BATCH_PUBLIC_KEY_QUBITS)
        conn.flush()

        corrections += teleport_public_key_batch(public_key_batch, epr_qubits, conn)

    writer.write(f"{corrections}\n".encode())
    print(
    f"Alice: sent public keys to {receiver_name} "
    f"({PUBLIC_KEY_QUBITS} qubits, {len(corrections)} correction bits)",
    flush=True
)


def is_valid_input_bits(bits: str) -> bool:
    return len(bits) == MSG_LENGTH and all(bit in "01" for bit in bits)


async def get_input_bits() -> str:
    env_bits = os.environ.get(INPUT_ENV_VAR)
    if env_bits is not None:
        bits = env_bits.strip()
        if is_valid_input_bits(bits):
            return bits
        print(
            f"Alice: invalid {INPUT_ENV_VAR}={env_bits!r}; using default zero string",
            flush=True
        )
        return "0" * MSG_LENGTH

    if not sys.stdin.isatty():
        return "0" * MSG_LENGTH

    while True:
        bits = await asyncio.to_thread(
            input,
            f"Alice — enter your {MSG_LENGTH}-bit input (e.g. {'0' * MSG_LENGTH}): ",
        )
        bits = bits.strip()
        if is_valid_input_bits(bits):
            return bits
        print(
            f"Invalid input. Please enter exactly {MSG_LENGTH} bits, e.g. {'0' * MSG_LENGTH}.",
            flush=True,
        )


def write_message(input_bits, private_key, writer) -> None:
    message = ""

    for i, char in enumerate(input_bits):
        bit = int(char)

        message += char

        for m in range(COPIES_PER_KEY):
            message += private_key[i][bit][m]

    writer.write(f"{message}\n".encode())
    return


async def run_alice(reader: StreamReader, writer: StreamWriter, receiver_name: str, private_key, send_signed_message: bool) -> None:
    state = STATE_WAITING_HI

    writer.write(b"HELLO:Alice\n")
    await writer.drain()

    print(
        f"[{state}] Alice: sent HELLO, waiting for {receiver_name}'s response",
        flush=True,
    )

    while state != STATE_DONE:
        if state == STATE_WAITING_HI:
            msg = (await reader.readline()).decode().strip()

            if msg.startswith("HELLO:"):
                print(
                    f"[{state}] Alice: received {receiver_name}'s HELLO",
                    flush=True,
                )
                state = STATE_SENDING_PUBLIC_KEY

        elif state == STATE_SENDING_PUBLIC_KEY:
            epr_socket = EPRSocket(receiver_name)
            conn = NetQASMConnection( "Alice", epr_sockets=[epr_socket], max_qubits=1000)

            send_public_keys_to_receiver(private_key, epr_socket, conn, writer, receiver_name)
            await writer.drain()

            conn.close()

            if send_signed_message:
                state = STATE_WAITING_FOR_INPUT
            else:
                state = STATE_DONE

        elif state == STATE_WAITING_FOR_INPUT:
            input_bits = await get_input_bits()
            print(f"[{state}] Alice: using input bits {input_bits}", flush=True)

            write_message(input_bits, private_key, writer)
            await writer.drain()

            print(
                f"Alice: sent signed message {input_bits} to {receiver_name} "
                f"(signature length={MSG_LENGTH * SIGNED_BLOCK_LENGTH})",
                flush=True
            )

            state = STATE_DONE


async def run_alice_to_charlie(reader: StreamReader, writer: StreamWriter) -> None:
    await run_alice(
        reader=reader,
        writer=writer,
        receiver_name="Charlie",
        private_key=PRIVATE_KEY,
        send_signed_message=False,
    )


async def run_alice_to_bob(reader: StreamReader, writer: StreamWriter) -> None:
    await run_alice(
        reader=reader,
        writer=writer,
        receiver_name="Bob",
        private_key=PRIVATE_KEY,
        send_signed_message=True,
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _here = Path(__file__).parent
    simulaqron_settings.read_from_file(_here / "simulaqron_settings.json")
    network_config.read_from_file(_here / "simulaqron_network.json")

    sockets_config = SocketsConfig(network_config, "default", NodeConfigType.APP)

PRIVATE_KEY = choose_private_key()

print(
    f"Alice: generated private keys for Bob and Charlie "
    f"(message length={MSG_LENGTH}, M={COPIES_PER_KEY}, public qubits per receiver={PUBLIC_KEY_QUBITS})",
    flush=True,
)

print("Alice: connecting to Charlie first...")
client_to_charlie = SimulaQronClassicalClient(sockets_config)
client_to_charlie.run_client("Charlie", run_alice_to_charlie)

print("Alice: connecting to Bob second...")
client_to_bob = SimulaQronClassicalClient(sockets_config)
client_to_bob.run_client("Bob", run_alice_to_bob)
