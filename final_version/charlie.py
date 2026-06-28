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

# ── States ──

STATE_WAITING_HI = "WAITING_HI"
STATE_WAITING_PUBLIC_KEY = "WAITING_PUBLIC_KEY"
STATE_WAITING_FORWARDED_MESSAGE = "WAITING_FORWARDED_MESSAGE"
STATE_VERIFICATION = "VERIFICATION"
STATE_DONE = "DONE"


# ── Constants ──
SECRET_KEY_LENGTH = 3  # Each secret key is a SECRET_KEY_LENGTH-bit string.
# A Hadamard fingerprint uses (SECRET_KEY_LENGTH + 1) qubit
FINGERPRINT_QUBITS = SECRET_KEY_LENGTH + 1

# Keep this same with alice
MSG_LENGTH = 9
COPIES_PER_KEY = 3

PUBLIC_KEY_QUBITS = FINGERPRINT_QUBITS * MSG_LENGTH * 2 * COPIES_PER_KEY
CORRECTION_BITS = 2 * PUBLIC_KEY_QUBITS
SIGNED_BLOCK_LENGTH = 1 + COPIES_PER_KEY * SECRET_KEY_LENGTH


# Attack simulation settings
ATTACK_ENV_VAR = "ATTACK_MODE"
ATTACK_NONE = "none"
ATTACK_FLIP_FIRST = "flip_first_bit"
ATTACK_FLIP_ALL = "flip_all_bits"
ATTACK_RANDOM_KEY = "random_key_only"
ATTACK_CHANGE_SECRET_KEY = "change_secret_key"

# Verification thresholds for a noisy channel, C1 < C2
# C1 is the strong-accept threshold, and C2 is the reject threshold
C1 = float(os.environ.get("C1", "0.15"))
C2 = float(os.environ.get("C2", "0.30"))
READOUT_NOISE = float(os.environ.get("READOUT_NOISE", "0.0"))

VERDICT_LEGITIMATE = "LEGITIMATE"
VERDICT_AMBIGUOUS = "AMBIGUOUS"
VERDICT_ILLEGITIMATE = "ILLEGITIMATE"
CHARLIE_CONN = None
CHARLIE_EPR_QUBITS = None


# ── Event Loop ──


def apply_corrections(epr_qubits, corrections) -> None:
    # Apply teleportation corrections to the received EPR halves
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


def apply_readout_noise(bit: int) -> int:
    # Flip the measured swap test result with probability READOUT_NOISE.
    if READOUT_NOISE <= 0.0:
        return bit

    if random.random() < READOUT_NOISE:
        return 1 - bit

    return bit


def flip_bit(bit: str) -> str:
    return "1" if bit == "0" else "0"


def random_secret_keys() -> str:
    keys = ""

    for _ in range(COPIES_PER_KEY):
        keys += random_bits(SECRET_KEY_LENGTH)

    return keys


def maybe_attack_message(msg_key: str) -> str:
    # Simulate Eve changing with Alice's signed message before Bob verifies it.
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
            flush=True,
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
            {"index": 0, "bit": 1, "secret_key": ["...", "...", "..."]},
            ...
        ]
    """
    expected_len = MSG_LENGTH * SIGNED_BLOCK_LENGTH
    # This error happend as MSG_LENGTH or COPIES_PER_KEY are different between Alice and Charlie
    if len(msg_key) != expected_len:
        raise ValueError(
            f"bad signed message length {len(msg_key)}, expected {expected_len}"
        )

    signed_blocks = []

    for i in range(MSG_LENGTH):
        start = i * SIGNED_BLOCK_LENGTH

        bit = int(msg_key[start])
        secret_keys = []

        # extract the M revealed secret keys after the message bit.
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
    # Prepare the Hadamard fingerprint state for one secret key
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
    # verify Bob's signed message using Charlie's public key copies.
    report = []

    for block in signed_blocks:
        i = block["index"]
        msg_bit = block["bit"]
        secret_keys = block["secret_keys"]

        for m, secret_key in enumerate(secret_keys):
            # reconstruct the fingerprint state from the revealed secret key
            reconstructed = prepare_hadamard_fingerprint(conn, secret_key)
            # select the matching public key copy for this message index, bit value and copy number
            start = ((2 * i + msg_bit) * COPIES_PER_KEY + m) * FINGERPRINT_QUBITS
            end = start + FINGERPRINT_QUBITS
            epr_qubits_to_compare = epr_qubits[start:end]

            # run a swap test
            ancilla = Qubit(conn)
            ancilla.H()
            for j in range(FINGERPRINT_QUBITS):
                controlled_swap(ancilla, reconstructed[j], epr_qubits_to_compare[j])

            ancilla.H()
            future_ancilla = ancilla.measure()

            # measure the compared states
            for j in range(FINGERPRINT_QUBITS):
                reconstructed[j].measure()
                epr_qubits_to_compare[j].measure()

            conn.flush()

            raw_ancilla_result = int(future_ancilla)
            ancilla_result = apply_readout_noise(raw_ancilla_result)
            passed = ancilla_result == 0

            report.append(
                {
                    "index": i,
                    "bit": msg_bit,
                    "copy": m,
                    "raw_ancilla": raw_ancilla_result,
                    "ancilla": ancilla_result,
                    "passed": passed,
                }
            )

    total_tests = len(report)
    fail_count = sum(1 for r in report if not r["passed"])

    lower_bound = C1 * total_tests
    upper_bound = C2 * total_tests

    if fail_count <= lower_bound:
        verdict = VERDICT_LEGITIMATE
    elif fail_count < upper_bound:
        verdict = VERDICT_AMBIGUOUS
    else:
        verdict = VERDICT_ILLEGITIMATE

    return verdict, fail_count, report


def print_verification_report(report, verdict, fail_count) -> None:
    # print verification report
    print("Charlie verification report:", flush=True)

    for i in range(MSG_LENGTH):
        bit_results = [item for item in report if item["index"] == i]

        message_bit = bit_results[0]["bit"]
        raw_ancillas = [item["raw_ancilla"] for item in bit_results]
        ancillas = [item["ancilla"] for item in bit_results]
        result = ["PASS" if item["passed"] else "FAIL" for item in bit_results]

        print(
            f"  bit {i}: message_bit={message_bit}, "
            f"raw_ancillas={raw_ancillas}, ancillas={ancillas}, result={result}",
            flush=True,
        )

    total = len(report)
    lower_bound = C1 * total
    upper_bound = C2 * total
    passed = total - fail_count
    fail_rate = fail_count / total if total > 0 else 0.0

    print(
        f"[VERIFICATION] Swap-test totals: PASS={passed}, FAIL={fail_count}, total={total}",
        flush=True,
    )
    print(f"[VERIFICATION] fail rate={fail_rate:.2%}", flush=True)
    # print(f"[VERIFICATION] thresholds: C1*total={lower_bound:.1f}, C2*total={upper_bound:.1f}", flush=True)
    # print(f"[VERIFICATION] READOUT_NOISE={READOUT_NOISE}, C1={C1}, C2={C2}", flush=True)

    if verdict == VERDICT_LEGITIMATE:
        print(
            f"[VERIFICATION] verdict: {verdict} - failures={fail_count} <= C1*total={lower_bound:.1f}",
            flush=True,
        )
        print("The message is strongly accepted.", flush=True)

    elif verdict == VERDICT_AMBIGUOUS:
        print(
            f"[VERIFICATION] verdict: {verdict} - C1*total={lower_bound:.1f} < failures={fail_count} < C2*total={upper_bound:.1f}",
            flush=True,
        )
        print(
            "The message is accepted only at a weak level and is not safely transferable.",
            flush=True,
        )

    elif verdict == VERDICT_ILLEGITIMATE:
        print(
            f"[VERIFICATION] verdict: {verdict} - failures={fail_count} >= C2*total={upper_bound:.1f}",
            flush=True,
        )
        print("The message is rejected as illegitimate.", flush=True)

    print(f"CHARLIE_FINAL_VERDICT:{verdict}", flush=True)
    # print(f"CHARLIE_FINAL_COUNTS:PASS={passed},FAIL={fail_count},TOTAL={total}", flush=True)


async def run_charlie(reader: StreamReader, writer: StreamWriter) -> None:
    global CHARLIE_CONN
    global CHARLIE_EPR_QUBITS

    state = STATE_WAITING_HI
    forwarded_msg_key = None

    while state != STATE_DONE:
        if state == STATE_WAITING_HI:
            print(f"[{state}] Charlie: waiting for HELLO", flush=True)

            msg = (await reader.readline()).decode().strip()
            print(f"[{state}] Charlie: received {msg}", flush=True)

            if msg == "HELLO:Alice":
                writer.write(b"HELLO:Charlie\n")
                await writer.drain()

                print(
                    f"[{state}] Charlie: received HELLO from Alice, responded",
                    flush=True,
                )
                state = STATE_WAITING_PUBLIC_KEY

            elif msg == "HELLO:Bob":
                writer.write(b"HELLO:Charlie\n")
                await writer.drain()

                print(
                    f"[{state}] Charlie: received HELLO from Bob, responded", flush=True
                )
                state = STATE_WAITING_FORWARDED_MESSAGE

        elif state == STATE_WAITING_PUBLIC_KEY:
            print(f"[{state}] Charlie: opening epr socket with Alice", flush=True)

            epr_socket = EPRSocket("Alice")
            conn = NetQASMConnection(
                "Charlie", epr_sockets=[epr_socket], max_qubits=1000
            )

            epr_qubits = epr_socket.recv_keep(number=PUBLIC_KEY_QUBITS)

            print(
                f"[{state}] Charlie: receiving {PUBLIC_KEY_QUBITS} public-key qubits from Alice",
                flush=True,
            )

            corrections = (await reader.readline()).decode().strip()
            print(
                f"[{state}] Charlie: received corrections of length {len(corrections)}",
                flush=True,
            )

            apply_corrections(epr_qubits, corrections)

            CHARLIE_CONN = conn
            CHARLIE_EPR_QUBITS = epr_qubits

            print(
                f"[{state}] Charlie: stored quantum public keys. "
                f"MSG_LENGTH={MSG_LENGTH}, COPIES_PER_KEY={COPIES_PER_KEY}, "
                f"PUBLIC_KEY_QUBITS={PUBLIC_KEY_QUBITS}, READOUT_NOISE={READOUT_NOISE}, "
                f"C1={C1}, C2={C2}",
                flush=True,
            )

            print(
                f"[{state}] Charlie: ready for Bob's forwarded signed message",
                flush=True,
            )

            state = STATE_DONE

        elif state == STATE_WAITING_FORWARDED_MESSAGE:
            print(f"[{state}] Charlie: waiting for Bob's forwarded message", flush=True)

            forwarded = (await reader.readline()).decode().strip()

            if forwarded.startswith("REJECTED_BY_BOB:"):
                bob_verdict = forwarded[len("REJECTED_BY_BOB:") :]
                print(
                    f"[{state}] Charlie: Bob did not forward the signature because Bob verdict={bob_verdict}",
                    flush=True,
                )
                print("Charlie: transferred signature NOT ACCEPTED", flush=True)
                state = STATE_DONE

            elif forwarded.startswith("SIGNED_MESSAGE:"):
                forwarded_msg_key = forwarded[len("SIGNED_MESSAGE:") :]
                print(
                    f"[{state}] Charlie: received forwarded signed message of length {len(forwarded_msg_key)}",
                    flush=True,
                )
                state = STATE_VERIFICATION

        elif state == STATE_VERIFICATION:
            signed_blocks = parse_signed_message(forwarded_msg_key)
            msg = signed_blocks_to_message(signed_blocks)

            print(f"[{state}] Charlie: verifying transferred message {msg}", flush=True)
            print(
                f"[{state}] Charlie: parsed {len(signed_blocks)} signed blocks",
                flush=True,
            )

            verdict, fail_count, report = verify_authenticity(
                CHARLIE_EPR_QUBITS,
                signed_blocks,
                CHARLIE_CONN,
            )

            print_verification_report(report, verdict, fail_count)

            if verdict == VERDICT_ILLEGITIMATE:
                print("Charlie: transferred signature REJECTED", flush=True)
            else:
                print("Charlie: transferred signature ACCEPTED", flush=True)

            CHARLIE_CONN.close()
            CHARLIE_CONN = None
            CHARLIE_EPR_QUBITS = None

            state = STATE_DONE


# ── Entry point ──

if __name__ == "__main__":
    _here = Path(__file__).parent
    simulaqron_settings.read_from_file(_here / "simulaqron_settings.json")
    network_config.read_from_file(_here / "simulaqron_network.json")

    sockets_config = SocketsConfig(network_config, "default", NodeConfigType.APP)
    server = SimulaQronClassicalServer(sockets_config, "Charlie")
    server.register_client_handler(run_charlie)
    print("Charlie: starting server...", flush=True)
    server.start_serving()
