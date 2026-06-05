import random
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


# ── Event Loop ────────────────────────────────────────────────────────────────


def apply_corrections(epr_qubits, corrections) -> None:
    for i in range(len(epr_qubits)):
        if corrections[2 * i + 1] == "1":
            epr_qubits[i].X()
        if corrections[2 * i] == "1":
            epr_qubits[i].Z()
    return


def controlled_swap(control: Qubit, left: Qubit, right: Qubit) -> None:
    """Fredkin gate using one Toffoli and two CNOTs."""
    right.cnot(left)
    toffoli_gate(control, left, right)
    right.cnot(left)


def verify_authenticity(epr_qubits, msg_key, conn):
    verdict = True
    for i in range(MSG_LENGTH):
        x = msg_key[
            (KEY_LENGTH * 2 + 1) * i + 1 : (KEY_LENGTH * 2 + 1) * i + KEY_LENGTH + 1
        ]
        theta = msg_key[
            (KEY_LENGTH * 2 + 1) * i + KEY_LENGTH + 1 : (KEY_LENGTH * 2 + 1) * i
            + 2 * KEY_LENGTH
            + 1
        ]
        qubits = []
        for j in range(KEY_LENGTH):
            q = Qubit(conn)
            if x[j] == "1":
                q.X()
            if theta[j] == "1":
                q.H()
            qubits.append(q)

        msg_bit = int(msg_key[(2 * KEY_LENGTH + 1) * i])
        epr_qubits_to_compare = epr_qubits[
            2 * KEY_LENGTH * i + msg_bit * KEY_LENGTH : 2 * KEY_LENGTH * i
            + msg_bit * KEY_LENGTH
            + KEY_LENGTH
        ]
        # performs the swap test
        ancilla = Qubit(conn)
        ancilla.H()
        for j in range(KEY_LENGTH):
            controlled_swap(ancilla, qubits[j], epr_qubits_to_compare[j])
        ancilla.H()
        future_ancilla = ancilla.measure()
        conn.flush()
        for j in range(KEY_LENGTH):
            _ = qubits[j].measure(), epr_qubits_to_compare[j].measure()
        conn.flush()
        ancilla = int(future_ancilla)
        if ancilla == 1:
            verdict = False
    conn.close()
    return verdict


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
            msg = msg_key[:: (2 * KEY_LENGTH + 1)]
            print(f"Bob: received message {msg}, and with key {msg_key}")
            state = STATE_VERIFICATION

        elif state == STATE_VERIFICATION:
            verdict = verify_authenticity(epr_qubits, msg_key, conn)
            if verdict:
                print(
                    f"[{state}] Bob: every swap test is SUCCESSFUL, message is most likely authentic"
                )
            else:
                print(f"[{state}] Bob: swap tests FAILED, message is NOT authentic")
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
