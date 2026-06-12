import random
import os
from asyncio import StreamReader, StreamWriter
from pathlib import Path

from netqasm.runtime.settings import set_simulator

set_simulator("simulaqron")

from netqasm.sdk import EPRSocket, Qubit  # noqa: E402
from netqasm.sdk.external import NetQASMConnection  # noqa: E402
from netqasm.sdk.toolbox.gates import toffoli_gate
from simulaqron.general.host_config import SocketsConfig
from simulaqron.sdk.protocol import SimulaQronClassicalServer
from simulaqron.settings import network_config, simulaqron_settings
from simulaqron.settings.network_config import NodeConfigType

# ── States ────────────────────────────────────────────────────────────────────

STATE_WAITING_HI = "WAITING_HI"
STATE_WAITING_PUBLIC_KEY = "WAITING_PUBLIC_KEY"
STATE_WAITING_MESSAGE = "WAITING_MESSAGE"
STATE_VERIFICATION = "VERIFICATION"
STATE_DONE = "DONE"


# ── Constants ─────────────────────────────────────────────────────────────────

KEY_LENGTH = 5
MSG_LENGTH = 10


ATTACK_ENV_VAR = "ATTACK_MODE"
ATTACK_NONE = "none"
ATTACK_FLIP_FIRST = "flip_first_bit"
ATTACK_FLIP_ALL = "flip_all_bits"
ATTACK_RANDOM_KEY = "random_key_only"
ATTACK_CHANGE_THETA = "change_theta"


# ── Event Loop ────────────────────────────────────────────────────────────────


def apply_corrections(epr_qubits, corrections) -> None:
    for i in range(len(epr_qubits)):
        if corrections[2 * i + 1] == "1":
            epr_qubits[i].X()
        if corrections[2 * i] == "1":
            epr_qubits[i].Z()
    return

def random_bits(n: int) -> str:
    return "".join(str(random.randint(0, 1)) for _ in range(n))

def flip_bit(bit: str) -> str:
    return "1" if bit == "0" else "0"


def maybe_attack_message(msg_key: str) -> str:
    ##Simulate Eve changing with Alice's signed message before Bob verifies it.
    attack_mode = os.environ.get(ATTACK_ENV_VAR, ATTACK_NONE).strip().lower()

    if attack_mode in ("", ATTACK_NONE):
        return msg_key

    block_len = 2 * KEY_LENGTH + 1
    expected_len = MSG_LENGTH * block_len

    if len(msg_key) != expected_len:
        print(
            f"[ATTACK] Cannot attack: bad msg_key length {len(msg_key)}, expected {expected_len}",
            flush=True,
        )
        return msg_key

    if any(c not in "01" for c in msg_key):
        print("[ATTACK] Cannot attack: msg_key is not binary", flush=True)
        return msg_key

    attacked = list(msg_key)

    if attack_mode == ATTACK_FLIP_FIRST:
        start = 0

        old_bit = attacked[start]
        new_bit = flip_bit(old_bit)
        attacked[start] = new_bit

        guessed_x = random_bits(KEY_LENGTH)
        guessed_theta = random_bits(KEY_LENGTH)

        attacked[start + 1 : start + 1 + KEY_LENGTH] = list(guessed_x)
        attacked[start + 1 + KEY_LENGTH : start + 1 + 2 * KEY_LENGTH] = list(
            guessed_theta
        )

        print(
            f"[ATTACK] flip_first_bit: bit {old_bit} -> {new_bit}, "
            f"guessed x={guessed_x}, theta={guessed_theta}",
            flush=True,
        )

    elif attack_mode == ATTACK_FLIP_ALL:
        for i in range(MSG_LENGTH):
            start = block_len * i

            old_bit = attacked[start]
            new_bit = flip_bit(old_bit)
            attacked[start] = new_bit

            guessed_x = random_bits(KEY_LENGTH)
            guessed_theta = random_bits(KEY_LENGTH)

            attacked[start + 1 : start + 1 + KEY_LENGTH] = list(guessed_x)
            attacked[start + 1 + KEY_LENGTH : start + 1 + 2 * KEY_LENGTH] = list(
                guessed_theta
            )

        print(
            "[ATTACK] flip_all_bits: flipped every message bit and guessed all keys",
            flush=True,
        )

    elif attack_mode == ATTACK_RANDOM_KEY:
        ##change x and theta only
        for i in range(MSG_LENGTH):
            start = block_len * i

            guessed_x = random_bits(KEY_LENGTH)
            guessed_theta = random_bits(KEY_LENGTH)

            attacked[start + 1 : start + 1 + KEY_LENGTH] = list(guessed_x)
            attacked[start + 1 + KEY_LENGTH : start + 1 + 2 * KEY_LENGTH] = list(
                guessed_theta
            )

        print(
            "[ATTACK] random_key_only: kept message bits but replaced all x and theta keys",
            flush=True,
        )

    elif attack_mode == ATTACK_CHANGE_THETA:
        for i in range(MSG_LENGTH):
            start = block_len * i
            theta_start = start + 1 + KEY_LENGTH
            theta_end = theta_start + KEY_LENGTH

            old_theta = attacked[theta_start:theta_end]
            new_theta = [flip_bit(bit) for bit in old_theta]

            attacked[theta_start:theta_end] = new_theta

        print(
            "[ATTACK] change_theta: kept message bits and x values, but flipped all theta values",
            flush=True,
        )

    else:
        print(f"[ATTACK] Unknown attack mode {attack_mode!r}; no attack applied")
        return msg_key

    attacked_msg_key = "".join(attacked)

    old_msg = msg_key[::block_len]
    new_msg = attacked_msg_key[::block_len]

    print(f"[ATTACK] original message: {old_msg}", flush=True)
    print(f"[ATTACK] attacked  message: {new_msg}", flush=True)

    return attacked_msg_key

def parse_signed_message(msg_key: str):
    """
    Parse Alice's signed message.
    Return a list of blocks:
        [
            {"index": 0, "bit": 1, "x": "...", "theta": "..."},
            ...
        ]
    """
    block_len = 2 * KEY_LENGTH + 1
    expected_len = MSG_LENGTH * block_len

    if len(msg_key) != expected_len:
        raise ValueError(
            f"bad signed message length {len(msg_key)}, expected {expected_len}"
        )

    signed_blocks = []

    for i in range(MSG_LENGTH):
        start = i * block_len

        bit = int(msg_key[start])
        x = msg_key[start + 1 : start + 1 + KEY_LENGTH]
        theta = msg_key[start + 1 + KEY_LENGTH : start + 1 + 2 * KEY_LENGTH]

        signed_blocks.append(
            {
                "index": i,
                "bit": bit,
                "x": x,
                "theta": theta,
            }
        )

    return signed_blocks

def signed_blocks_to_message(signed_blocks) -> str:
    return "".join(str(block["bit"]) for block in signed_blocks)

def controlled_swap(control: Qubit, left: Qubit, right: Qubit) -> None:
    """Fredkin gate using one Toffoli and two CNOTs."""
    right.cnot(left)
    toffoli_gate(control, left, right)
    right.cnot(left)


def verify_authenticity(epr_qubits, signed_blocks, conn):
    verdict = True
    report = []

    for block in signed_blocks:
        i = block["index"]
        msg_bit = block["bit"]
        x = block["x"]
        theta = block["theta"]

        qubits = []
        for j in range(KEY_LENGTH):
            q = Qubit(conn)
            if x[j] == "1":
                q.X()
            if theta[j] == "1":
                q.H()
            qubits.append(q)

        start = 2 * KEY_LENGTH * i + msg_bit * KEY_LENGTH
        end = start + KEY_LENGTH
        epr_qubits_to_compare = epr_qubits[start:end]

        ancilla = Qubit(conn)
        ancilla.H()

        for j in range(KEY_LENGTH):
            controlled_swap(ancilla, qubits[j], epr_qubits_to_compare[j])

        ancilla.H()
        future_ancilla = ancilla.measure()

        for j in range(KEY_LENGTH):
            qubits[j].measure()
            epr_qubits_to_compare[j].measure()

        conn.flush()

        ancilla_result = int(future_ancilla)
        passed = ancilla_result == 0

        if not passed:
            verdict = False

        report.append(
            {
                "index": i,
                "bit": msg_bit,
                "x": x,
                "theta": theta,
                "ancilla": ancilla_result,
                "passed": passed,
            }
        )

    return verdict, report

def print_verification_report(report) -> None:
    print("Bob verification report:", flush=True)

    for item in report:
        result = "PASS" if item["passed"] else "FAIL"

        print(
            f"  bit {item['index']}: "
            f"message_bit={item['bit']}, "
            f"ancilla={item['ancilla']}, "
            f"result={result}",
            flush=True,
        )

def delete_unused_public_keys(epr_qubits, signed_blocks, conn) -> str:
    outcome_futures = []

    for block in signed_blocks:
        i = block["index"]
        msg_bit = block["bit"]
        unused_bit = 1 - msg_bit

        start = 2 * KEY_LENGTH * i + unused_bit * KEY_LENGTH
        end = start + KEY_LENGTH

        for q in epr_qubits[start:end]:
            q.H()
            outcome_futures.append(q.measure())

    conn.flush()

    certificate = ""
    for outcome_future in outcome_futures:
        certificate += str(int(outcome_future))

    return certificate


async def run_bob(reader: StreamReader, writer: StreamWriter) -> None:
    state = STATE_WAITING_HI
    while state != STATE_DONE:
        if state == STATE_WAITING_HI:
            print(f"[{state}] Bob: waiting for message")
            msg = (await reader.readline()).decode().strip()
            print(f"[{state}] Bob: received {msg}")
            if msg.startswith("HELLO:"):
                writer.write(b"HELLO:Bob\n")
                print(f"[{state}] Bob: received HELLO, responded")
                state = STATE_WAITING_PUBLIC_KEY

        elif state == STATE_WAITING_PUBLIC_KEY:
            print(f"[{state}] Bob: opening epr socket with Alice")
            epr_socket = EPRSocket("Alice")
            conn = NetQASMConnection("Bob", epr_sockets=[epr_socket], max_qubits=1000)
            epr_qubits = epr_socket.recv_keep(number=KEY_LENGTH * MSG_LENGTH * 2)
            print(f"[{state}] Bob: opened epr socket with Alice")
            corrections = (await reader.readline()).decode().strip()
            print(f"[{state}] Bob: received corrections {corrections}")
            apply_corrections(epr_qubits, corrections)
            print(f"[{state}] Bob: applied corrections")
            state = STATE_WAITING_MESSAGE

        elif state == STATE_WAITING_MESSAGE:
            msg_key = (await reader.readline()).decode().strip()
            print(f"Bob: received original signed message {msg_key}")

            msg_key = maybe_attack_message(msg_key)
            signed_blocks = parse_signed_message(msg_key)

            msg = signed_blocks_to_message(signed_blocks)
            print(f"Bob: verifying message {msg}")
            print(f"Bob: parsed signed blocks {signed_blocks}")
            state = STATE_VERIFICATION

        elif state == STATE_VERIFICATION:
            verdict, report = verify_authenticity(epr_qubits, signed_blocks, conn)

            print_verification_report(report)

            if verdict:
                print(
                    f"[{state}] Bob: every swap test is SUCCESSFUL, message is most likely authentic"
                )
            else:
                print(f"[{state}] Bob: swap tests FAILED, message is NOT authentic")

            deletion_certificate = delete_unused_public_keys(epr_qubits, signed_blocks, conn)
            writer.write(f"DELETE_CERT:{deletion_certificate}\n".encode())

            print(
                f"[{state}] Bob: deleted unused public keys and sent deletion certificate "
                f"of length {len(deletion_certificate)}",
                flush=True,
            )

            conn.close()
            state = STATE_DONE


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _here = Path(__file__).parent
    simulaqron_settings.read_from_file(_here / "simulaqron_settings.json")
    network_config.read_from_file(_here / "simulaqron_network.json")

    sockets_config = SocketsConfig(network_config, "default", NodeConfigType.APP)
    server = SimulaQronClassicalServer(sockets_config, "Bob")
    server.register_client_handler(run_bob)
    print("Bob: starting server...", flush=True)
    server.start_serving()
