import os
import random
from asyncio import StreamReader, StreamWriter
from pathlib import Path

from netqasm.runtime.settings import set_simulator
set_simulator("simulaqron")

from netqasm.sdk import EPRSocket, Qubit  
from netqasm.sdk.external import NetQASMConnection  
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
SECRET_KEY_LENGTH = 3
FINGERPRINT_QUBITS = SECRET_KEY_LENGTH + 1

##Keep this same with alice
MSG_LENGTH = 9
COPIES_PER_KEY = 3

PUBLIC_KEY_QUBITS = FINGERPRINT_QUBITS * MSG_LENGTH * 2 * COPIES_PER_KEY
CORRECTION_BITS = 2 * PUBLIC_KEY_QUBITS
SIGNED_BLOCK_LENGTH = 1 + COPIES_PER_KEY * SECRET_KEY_LENGTH


ATTACK_ENV_VAR = "ATTACK_MODE"
ATTACK_NONE = "none"
ATTACK_FLIP_FIRST = "flip_first_bit"
ATTACK_FLIP_ALL = "flip_all_bits"
ATTACK_RANDOM_KEY = "random_key_only"
ATTACK_CHANGE_SECRET_KEY = "change_secret_key"

# Verification thresholds for a noisy channel, C1 < C2
C1 = 0.20
C2 = 0.45

VERDICT_LEGITIMATE = "LEGITIMATE"
VERDICT_AMBIGUOUS = "AMBIGUOUS"
VERDICT_ILLEGITIMATE = "ILLEGITIMATE"


# ── Event Loop ────────────────────────────────────────────────────────────────


def apply_corrections(epr_qubits, corrections) -> None:
    expected_len = 2 * len(epr_qubits)

    if len(corrections) != expected_len:
        raise ValueError(
            f"bad corrections length {len(corrections)}, expected {expected_len}"
        )

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

def random_secret_keys() -> str:
    keys = ""

    for _ in range(COPIES_PER_KEY):
        keys += random_bits(SECRET_KEY_LENGTH)

    return keys


def maybe_attack_message(msg_key: str) -> str:
    ##Simulate Eve changing with Alice's signed message before Bob verifies it.
    attack_mode = os.environ.get(ATTACK_ENV_VAR, ATTACK_NONE).strip().lower()

    if attack_mode in ("", ATTACK_NONE):
        return msg_key

    expected_len = MSG_LENGTH * SIGNED_BLOCK_LENGTH

    if len(msg_key) != expected_len:
        print(
            f"[ATTACK] Cannot attack: bad msg_key length {len(msg_key)}, expected {expected_len}",
            flush=True,
        )
        return msg_key

    attacked = list(msg_key)

    if attack_mode == ATTACK_FLIP_FIRST:
        start = 0

        old_bit = attacked[start]
        new_bit = flip_bit(old_bit)
        attacked[start] = new_bit

        guessed_keys = random_secret_keys()
        attacked[start + 1 : start + SIGNED_BLOCK_LENGTH] = list(guessed_keys)

        print(
            f"[ATTACK] flip_first_bit: bit {old_bit} -> {new_bit}, guessed {COPIES_PER_KEY} secret keys",
            flush=True
        )

    elif attack_mode == ATTACK_FLIP_ALL:
        for i in range(MSG_LENGTH):
            start = SIGNED_BLOCK_LENGTH * i

            old_bit = attacked[start]
            new_bit = flip_bit(old_bit)
            attacked[start] = new_bit

            guessed_keys = random_secret_keys()
            attacked[start + 1 : start + SIGNED_BLOCK_LENGTH] = list(guessed_keys)

        print(
            "[ATTACK] flip_all_bits: flipped every message bit and guessed all secret keys",
            flush=True,
        )

    elif attack_mode == ATTACK_RANDOM_KEY:
        for i in range(MSG_LENGTH):
            start = SIGNED_BLOCK_LENGTH * i

            guessed_keys = random_secret_keys()
            attacked[start + 1 : start + SIGNED_BLOCK_LENGTH] = list(guessed_keys)

        print(
            "[ATTACK] random_key_only: kept message bits but replaced all secret keys",
            flush=True,
        )

    elif attack_mode == ATTACK_CHANGE_SECRET_KEY:
        for i in range(MSG_LENGTH):
            start = SIGNED_BLOCK_LENGTH * i
            key_start = start + 1
            key_end = start + SIGNED_BLOCK_LENGTH

            old_keys = attacked[key_start:key_end]
            new_keys = [flip_bit(bit) for bit in old_keys]

            attacked[key_start:key_end] = new_keys

        print(
            "[ATTACK] change_secret_key: kept message bits but flipped all secret-key bits",
            flush=True,
        )

    else:
        print(f"[ATTACK] Unknown attack mode {attack_mode!r}, no attack applied")
        return msg_key

    attacked_msg_key = "".join(attacked)

    old_msg = msg_key[::SIGNED_BLOCK_LENGTH]
    new_msg = attacked_msg_key[::SIGNED_BLOCK_LENGTH]

    print(f"[ATTACK] original message: {old_msg}", flush=True)
    print(f"[ATTACK] attacked  message: {new_msg}", flush=True)

    return attacked_msg_key


def parse_signed_message(msg_key: str):
    """
    Parse Alice's signed message.
    Return a list of blocks:
        [
            {"index": 0, "bit": 1, "secret_key": "..."},
            ...
        ]
    """
    expected_len = MSG_LENGTH * SIGNED_BLOCK_LENGTH

    if len(msg_key) != expected_len:
        raise ValueError(
            f"bad signed message length {len(msg_key)}, expected {expected_len}"
        )

    signed_blocks = []

    for i in range(MSG_LENGTH):
        start = i * SIGNED_BLOCK_LENGTH

        bit = int(msg_key[start])
        secret_keys = []

        for m in range(COPIES_PER_KEY):
            key_start = start + 1 + m * SECRET_KEY_LENGTH
            key_end = key_start + SECRET_KEY_LENGTH
            secret_keys.append(msg_key[key_start:key_end])

        signed_blocks.append(
            {
                "index": i,
                "bit": bit,
                "secret_keys": secret_keys,
            }
        )

    return signed_blocks


def signed_blocks_to_message(signed_blocks) -> str:
    return "".join(str(block["bit"]) for block in signed_blocks)


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


def controlled_swap(control: Qubit, left: Qubit, right: Qubit) -> None:
    """Fredkin gate using one Toffoli and two CNOTs."""
    right.cnot(left)
    toffoli_gate(control, left, right)
    right.cnot(left)


def verify_authenticity(epr_qubits, signed_blocks, conn):
    report = []

    for block in signed_blocks:
        i = block["index"]
        msg_bit = block["bit"]
        secret_keys = block["secret_keys"]

        for m, secret_key in enumerate(secret_keys):
            reconstructed = prepare_hadamard_fingerprint(conn, secret_key)

            start = ((2 * i + msg_bit) * COPIES_PER_KEY + m) * FINGERPRINT_QUBITS
            end = start + FINGERPRINT_QUBITS
            epr_qubits_to_compare = epr_qubits[start:end]

            ancilla = Qubit(conn)
            ancilla.H()

            for j in range(FINGERPRINT_QUBITS):
                controlled_swap(ancilla, reconstructed[j], epr_qubits_to_compare[j])

            ancilla.H()
            future_ancilla = ancilla.measure()

            for j in range(FINGERPRINT_QUBITS):
                reconstructed[j].measure()
                epr_qubits_to_compare[j].measure()

            conn.flush()

            ancilla_result = int(future_ancilla)
            passed = ancilla_result == 0

            report.append(
                {
                    "index": i,
                    "bit": msg_bit,
                    "copy": m,
                    "ancilla": ancilla_result,
                    "passed": passed,
                }
            )
    
    total_tests = len(report)
    fail_count = sum(1 for r in report if not r["passed"])

    if fail_count <= C1 * total_tests:
        verdict = VERDICT_LEGITIMATE
    elif fail_count < C2 * total_tests:
        verdict = VERDICT_AMBIGUOUS
    else:
        verdict = VERDICT_ILLIGETIMATE
    return verdict, fail_count, report


def print_verification_report(report, verdict, fail_count) -> None:
    print("Bob verification report:", flush=True)

    for i in range(MSG_LENGTH):
        bit_results = [item for item in report if item["index"] == i]

        message_bit = bit_results[0]["bit"]
        ancillas = [item["ancilla"] for item in bit_results]
        passed = all(item["passed"] for item in bit_results)
        result = ["PASS" if item["passed"] else "FAIL" for item in bit_results]

        print(f"  bit {i}: message_bit={message_bit}, ancillas={ancillas}, result={result}", flush=True)

    total = len(report)
    lower_bound = C1 * total
    upper_bound = C2 * total
    passed = total - fail_count
    
    print(f"[VERIFICATION] Swap-test totals: PASS={passed}, FAIL={fail_count}, total={total}", flush=True)

    if verdict == VERDICT_LEGITIMATE:
        print(f"[VERIFICATION] verdict: {verdict} - failures={fail_count} <= C1*M={lower_bound:.1f}:", flush=True)
        print("The message is most likely authentic.", flush=True)
    elif verdict == VERDICT_AMBIGUOUS:
        print(f"[VERIFICATION] verdict: {verdict} - C1*M={lower_bound:.1f} < failures={fail_count} < C2={upper_bound:.1f}", flush=True)
        print("The message is probably legitimate, but it looks like Alice is trying to cheat, " + 
              "and therefore someone else might find the message illegitimate.", flush=True)
    elif verdict == VERDICT_ILLEGITIMATE:
        print(f"[VERIFICATION] verdict: {verdict} - fail rate={fail_count} >= C2*M={upper_bound:.1f}:", flush=True)
        print("The message is illegitimate.")

async def run_bob(reader: StreamReader, writer: StreamWriter) -> None:
    state = STATE_WAITING_HI

    while state != STATE_DONE:
        if state == STATE_WAITING_HI:
            print(f"[{state}] Bob: waiting for message")
            msg = (await reader.readline()).decode().strip()

            print(f"[{state}] Bob: received {msg}")

            if msg.startswith("HELLO:"):
                writer.write(b"HELLO:Bob\n")
                await writer.drain()

                print(f"[{state}] Bob: received HELLO, responded")

                state = STATE_WAITING_PUBLIC_KEY

        elif state == STATE_WAITING_PUBLIC_KEY:
            print(f"[{state}] Bob: opening epr socket with Alice")

            epr_socket = EPRSocket("Alice")
            conn = NetQASMConnection("Bob", epr_sockets=[epr_socket], max_qubits=1000)

            epr_qubits = epr_socket.recv_keep(number=PUBLIC_KEY_QUBITS)
            print(
                f"[{state}] Bob: opened epr socket with Alice for {PUBLIC_KEY_QUBITS} public-key qubits",
                flush=True
            )

            corrections = (await reader.readline()).decode().strip()
            #print(f"[{state}] Bob: received corrections {corrections}")
            print(f"[{state}] Bob: received corrections of length {len(corrections)}")

            apply_corrections(epr_qubits, corrections)
            print(f"[{state}] Bob: applied corrections")

            state = STATE_WAITING_MESSAGE

        elif state == STATE_WAITING_MESSAGE:
            msg_key = (await reader.readline()).decode().strip()
            #print(f"Bob: received original signed message {msg_key}")
            print(f"Bob: received signed message of length {len(msg_key)}")

            msg_key = maybe_attack_message(msg_key)
            signed_blocks = parse_signed_message(msg_key)

            msg = signed_blocks_to_message(signed_blocks)
            print(f"Bob: verifying message {msg}")
            #print(f"Bob: parsed signed blocks {signed_blocks}")
            print(f"Bob: parsed {len(signed_blocks)} signed blocks")

            state = STATE_VERIFICATION

        elif state == STATE_VERIFICATION:
            verdict, fail_count, report = verify_authenticity(epr_qubits, signed_blocks, conn)

            print_verification_report(report, verdict, fail_count)

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
