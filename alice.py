import asyncio
import os
import random
import sys
from asyncio import StreamReader, StreamWriter
from pathlib import Path

from netqasm.runtime.settings import set_simulator

set_simulator("simulaqron")

from netqasm.sdk import EPRSocket, Qubit  # noqa: E402
from netqasm.sdk.external import NetQASMConnection  # noqa: E402
from simulaqron.general.host_config import SocketsConfig
from simulaqron.sdk.protocol import SimulaQronClassicalClient
from simulaqron.settings import network_config, simulaqron_settings
from simulaqron.settings.network_config import NodeConfigType

# ── States ────────────────────────────────────────────────────────────────────

STATE_WAITING_HI = "WAITING_HI"
STATE_CREATING_KEYS = "CREATING_KEYS"
STATE_WAITING_FOR_INPUT = "WAITING_FOR_INPUT"
STATE_DONE = "DONE"


# ── Constants ─────────────────────────────────────────────────────────────────

KEY_LENGTH = 5
MSG_LENGTH = 5
INPUT_ENV_VAR = "ALICE_INPUT_BITS"


# ── Event Loop ────────────────────────────────────────────────────────────────


def choose_private_key() -> list[tuple[tuple[str]]]:
    private_key = []
    for _ in range(MSG_LENGTH):
        x0, x1 = "", ""
        theta0, theta1 = "", ""
        for _ in range(KEY_LENGTH):
            x0 += str(random.randint(0, 1))
            x1 += str(random.randint(0, 1))
            theta0 += str(random.randint(0, 1))
            theta1 += str(random.randint(0, 1))
        private_key.append(((x0, theta0), (x1, theta1)))
    print(f"[CREATING_KEYS] Alice: chose private key {private_key}")
    return private_key


def create_public_key(private_key, conn) -> list[tuple[list[Qubit]]]:
    qubits = []
    for i in range(MSG_LENGTH):
        qubits_list0 = []
        qubits_list1 = []
        for k in range(KEY_LENGTH):
            q0 = Qubit(conn)
            q1 = Qubit(conn)
            if private_key[i][0][0][k] == "1":
                q0.X()
            if private_key[i][0][1][k] == "1":
                q0.H()
            if private_key[i][1][0][k] == "1":
                q1.X()
            if private_key[i][1][1][k] == "1":
                q1.H()

            qubits_list0.append(q0)
            qubits_list1.append(q1)
        qubits.append((qubits_list0, qubits_list1))
    return qubits


def teleport_public_key(public_key, epr_qubits, conn, writer) -> None:
    corrections = ""
    for i in range(MSG_LENGTH):
        for j in range(2):
            for k in range(KEY_LENGTH):
                public_key[i][j][k].cnot(
                    epr_qubits[2 * KEY_LENGTH * i + KEY_LENGTH * j + k]
                )
                public_key[i][j][k].H()
                m1_future = public_key[i][j][k].measure()
                m2_future = epr_qubits[
                    2 * KEY_LENGTH * i + KEY_LENGTH * j + k
                ].measure()
                conn.flush()
                corrections += str(int(m1_future))
                corrections += str(int(m2_future))
    writer.write(f"{corrections}\n".encode())
    return


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
            flush=True,
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
        message += char
        message += private_key[i][int(char)][0]  # adds x
        message += private_key[i][int(char)][1]  # adds theta
    writer.write(f"{message}\n".encode())
    return


async def run_alice(reader: StreamReader, writer: StreamWriter) -> None:
    writer.write(b"HELLO:Alice\n")
    state = STATE_WAITING_HI
    print(f"[{state}] Alice: sent HELLO, waiting for Bob's response")
    while state != STATE_DONE:
        if state == STATE_WAITING_HI:
            msg = (await reader.readline()).decode().strip()
            if msg.startswith("HELLO:"):
                print(f"[{state}] Alice: received Bob's HELLO")
                state = STATE_CREATING_KEYS

        elif state == STATE_CREATING_KEYS:
            private_key = choose_private_key()
            print(f"[{state}] Alice: chose private key")

            epr_socket = EPRSocket("Bob")
            conn = NetQASMConnection(
                "Alice",
                epr_sockets=[epr_socket],
                max_qubits=100,
            )
            public_key = create_public_key(private_key, conn)
            print(f"[{state}] Alice: created public key")
            epr_qubits = epr_socket.create_keep(number=KEY_LENGTH * MSG_LENGTH * 2)
            print(f"[{state}] Alice: opened epr socket with Bob")
            teleport_public_key(public_key, epr_qubits, conn, writer)
            conn.close()
            print(f"[{state}] Alice: teleported public key to Bob")
            state = STATE_WAITING_FOR_INPUT

        elif state == STATE_WAITING_FOR_INPUT:
            input_bits = await get_input_bits()
            print(f"[{state}] Alice: using input bits {input_bits}")
            write_message(input_bits, private_key, writer)
            state = STATE_DONE


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _here = Path(__file__).parent
    simulaqron_settings.read_from_file(_here / "simulaqron_settings.json")
    network_config.read_from_file(_here / "simulaqron_network.json")

    sockets_config = SocketsConfig(network_config, "default", NodeConfigType.APP)
    client = SimulaQronClassicalClient(sockets_config)
    print("Alice: connecting to Bob...")
    client.run_client("Bob", run_alice)
