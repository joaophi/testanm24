from asyncio import Queue, QueueFull, StreamReader, StreamWriter, Task, TaskGroup
import asyncio
from contextlib import contextmanager
from functools import partial
import logging
import signal
import sys
from typing import Any, Optional, TypedDict

START_COMMAND = 0x94
MAC_COMMAND = 0xC4
VERSION_COMMAND = 0xC0
UNKNOWN_COMMAND = 0x80
PING_COMMAND = 0xF7
PUSH_COMMAND = 0xB4
OK = 0xFE
MY_HOME = 0xE9
ISEC = 0xE7
XOR_COMMAND = 0xFB
CONNECTION_COMMAND = 0xE5


class MyHomeCommands:
    ARM = (0x41, b"\x41")
    DISARM = (0x44, b"")
    PANIC_AUDIBLE = (0x45, b"\x01")
    PANIC_SILENT = (0x45, b"\x00")
    STATUS = (0x5A, b"")
    MESSAGES = (0xF1, b"")


def my_home_to_str(data: bytes) -> "str | Status":
    if data[0] == OK:
        return "OK"
    elif data[0] == 0x21 and data[-1] == 0x21:
        password = data[1:5].decode("ascii")
        command = data[5]
        data = data[6:-1]
        if command == MyHomeCommands.ARM[0]:
            command = "ARM"
        elif command == MyHomeCommands.DISARM[0]:
            command = "DISARM"
        elif (
            command == MyHomeCommands.PANIC_AUDIBLE[0]
            and data == MyHomeCommands.PANIC_AUDIBLE[1]
        ):
            command = "PANIC_AUDIBLE"
        elif (
            command == MyHomeCommands.PANIC_SILENT[0]
            and data == MyHomeCommands.PANIC_SILENT[1]
        ):
            command = "PANIC_SILENT"
        elif command == MyHomeCommands.STATUS[0]:
            command = "STATUS"
        elif command == 0x00 and data[2] == MyHomeCommands.MESSAGES[0]:
            command = "MESSAGES"
            if data[5] == SYNC_EVENT:
                command += " EVENT"
            elif data[5] == SYNC_NAME:
                command += " NAME"
            elif data[5] == SYNC_USER:
                command += " USER"
            elif data[5] == SYNC_ZONE:
                command += " ZONE"
            else:
                command += f" 0x{data[5]:02x}"
        else:
            command = f"0x{command:02x}" + (f": {data.hex(':')}" if data else "")
        return f"CMD = {command}, PASSWORD = {password}"
    else:
        try:
            type, messages = parse_sync(data)
            if type == SYNC_EVENT:
                sync = "EVENT"
            elif type == SYNC_NAME:
                sync = "NAME"
            elif type == SYNC_USER:
                sync = "USER"
            elif type == SYNC_ZONE:
                sync = "ZONE"
            else:
                sync = f"0x{type:02x}"
            return f"SYNC = {sync}, MESSAGES = {messages}"
        except Exception:
            pass

        try:
            status = parse_status(data)
            return status
        except Exception:
            pass

        return data.hex(":")


def command_to_str(command: int, data: bytes | None) -> str:
    # print(f"Raw: {command:02x} {data.hex(':')}")
    if command == START_COMMAND:
        return "START"
    elif command == CONNECTION_COMMAND:
        return "CONNECTION"
    elif command == XOR_COMMAND:
        return "XOR"
    elif command == MAC_COMMAND:
        return "MAC" + (f": {data.hex(':')}" if data else "")
    elif command == VERSION_COMMAND:
        return "VERSION" + (f": {data.decode('ascii')}" if data else "")
    elif command == UNKNOWN_COMMAND:
        return "UNKNOWN" + (f": {data.hex(':')}" if data else "")
    elif command == PING_COMMAND:
        return "PING"
    elif command == PUSH_COMMAND:
        return "PUSH" + (f": {data.hex(':')}" if data else "")
    elif command == OK:
        return "OK"
    elif command == ISEC:
        return "ISEC" + (f": {data.hex(':')}" if data else "")
    elif command == MY_HOME:
        return "MY_HOME" + (f": {my_home_to_str(data)}" if data else "")
    else:
        return f"0x{command:02x}" + (f": {data.hex(':')}" if data else "")


def create_command(command: int, data: bytes | None = None) -> bytes:
    if data is None:
        data = bytes()
    data = bytes([len(data) + 1, command, *data])
    return bytes([*data, checksum(data)])


def connection_data(mac: bytes) -> bytes:
    uuid = b""
    token = b""
    return bytes(
        [
            0x06,
            *uuid.zfill(8),
            *mac,
            checksum(token),
            0x45,
            *[0x00 for _ in range(4)],
            0x03,
            0x00,  # LANGUAGE,
            *token,
        ]
    )


def encrypt(data: bytes, key: int) -> bytes:
    return bytes([x ^ key for x in data])


class Battery(TypedDict):
    envoltorio: bool
    primeiroNivel: bool
    segundoNivel: bool
    terceiroNivel: bool
    envoltorioPisc: bool


class Zone(TypedDict):
    open: bool
    violated: bool
    anulated: bool
    stay: bool
    enabled: bool
    low_battery: bool


class Status(TypedDict):
    version: int
    partitionedPanel: bool
    partitionAArmed: bool
    partitionBArmed: bool
    sirenTriggered: bool
    battery: Battery
    zones: list[Zone]
    pgm: bool
    no_energy: bool


def parse_status(data: bytes) -> Status:
    open_zones = int.from_bytes(data[:3], byteorder="little")
    violated_zones = int.from_bytes(data[6:9], byteorder="little")
    anulated_zones = int.from_bytes(data[12:15], byteorder="little")
    stay_zones = int.from_bytes(data[50:53], byteorder="little")
    enabled_zones = int.from_bytes(data[47:50], byteorder="little")
    low_battery = int.from_bytes(data[38:41], byteorder="little")

    return {
        "version": int(data[19]),
        "partitionedPanel": bool(data[20] & (1 << 0)),
        "partitionAArmed": bool(data[21] & (1 << 0)),
        "partitionBArmed": bool(data[21] & (1 << 1)),
        "sirenTriggered": bool(data[37] & (1 << 2)),
        "battery": {
            "envoltorio": bool(data[30] & (1 << 0)),
            "primeiroNivel": bool(data[30] & (1 << 1)),
            "segundoNivel": bool(data[30] & (1 << 2)),
            "terceiroNivel": bool(data[30] & (1 << 3)),
            "envoltorioPisc": bool(data[30] & (1 << 4)),
        },
        "zones": [
            {
                "open": bool(open_zones & (1 << i)),
                "violated": bool(violated_zones & (1 << i)),
                "anulated": bool(anulated_zones & (1 << i)),
                "stay": bool(stay_zones & (1 << i)),
                "enabled": bool(enabled_zones & (1 << i)),
                "low_battery": bool(low_battery & (1 << i)),
            }
            for i in range(24)
        ],
        "pgm": bool(data[37] & (1 << 7)),
        "no_energy": bool(data[28] & (1 << 0)),
    }


CHAR_MAP = {
    126: 226,
    127: 227,
    128: 225,
    129: 224,
    130: 234,
    131: 233,
    132: 237,
    133: 244,
    134: 243,
    135: 245,
    136: 250,
    137: 252,
    138: 231,
    139: 193,
    140: 192,
    141: 195,
    142: 194,
    143: 201,
    144: 202,
    145: 205,
    146: 211,
    147: 212,
    148: 213,
    149: 218,
    150: 220,
    151: 199,
    158: 176,
    159: 185,
    160: 178,
    161: 179,
}


def parse_char(char: int) -> str:
    return chr(CHAR_MAP.get(char, char))


def parse_sync(data: bytes) -> tuple[int, list[str]]:
    if data[1] != MyHomeCommands.MESSAGES[0] or data[7] != 0xE0:
        raise Exception("Invalid data")

    type = data[6]
    result = []
    buffer = ""
    idx = 9
    while idx < len(data):
        if data[idx] == 0x00 or len(buffer) >= 14:
            result.append(buffer.strip())
            buffer = ""
        else:
            buffer += parse_char(data[idx])
        idx += 1

    if buffer:
        result.append(buffer[:-1].strip())

    return type, result


def my_home_data(password: str, command: int, data: bytes = bytes()) -> bytes:
    return bytes([0x21, *map(ord, password), command, *data, 0x21])


SYNC_EVENT = 0x30
SYNC_NAME = 0x31
SYNC_USER = 0x32
SYNC_ZONE = 0x33


def sync_data(type: int, indexes: bytes = bytes([0x00])) -> bytes:
    return bytes(
        [
            0x00,
            0x00,
            0x00,
            MyHomeCommands.MESSAGES[0],  # COMANDO_MENSAGENS
            0x00,
            len(indexes) + 2,
            type,
            0xE0,
            *indexes,
        ]
    )


def checksum(data: bytes) -> int:
    i = 0
    for x in data:
        i ^= x
    return i ^ 255


class Listenable[T]:
    def __init__(self):
        self._listeners: list[Queue[T]] = []

    def emit(self, data: Any):
        for listener in self._listeners:
            try:
                listener.put_nowait(data)
            except QueueFull:
                pass

    def add_listener(self, queue: Optional[Queue[T]] = None) -> Queue[T]:
        queue = queue or Queue[T]()
        self._listeners.append(queue)
        return queue

    def remove_listener(self, queue: Queue[T]):
        self._listeners.remove(queue)

    def listeners(self) -> int:
        return len(self._listeners)

    @contextmanager
    def listener(self, queue: Optional[Queue[T]] = None):
        queue = self.add_listener(queue)
        try:
            yield queue
        finally:
            self.remove_listener(queue)


async def read_command(reader: StreamReader):
    [length] = await reader.read(1)

    if length in [PING_COMMAND, OK]:
        return length, bytes()

    data = await reader.read(length)
    [checksum_] = await reader.read(1)
    if checksum_ != checksum(bytes([length, *data])):
        raise Exception(f"Invalid checksum {checksum_:02x} for data: {data}")

    return data[0], data[1:]


async def send_command(
    writer: StreamWriter,
    command: int,
    data: bytes | None = None,
    key: int | None = None,
):
    if command in [PING_COMMAND, OK]:
        data = bytes([command])
    else:
        data = create_command(command, data)

    if key:
        data = encrypt(data, key)

    writer.write(data)
    await writer.drain()


OPEN_CONNECTIONS: dict[str, tuple[StreamWriter, Listenable[tuple[int, bytes]]]] = {}


async def handle(
    _logger: logging.Logger,
    reader: StreamReader,
    writer: StreamWriter,
):
    _logger.info("New connection")

    mac = None
    version = None

    receive = Listenable[tuple[int, bytes]]()

    async with TaskGroup() as tg:

        async def __downstream_client(data: bytes):
            logger = _logger.getChild("downstream_client")

            nonlocal mac
            mac = data[9:15]
            logger.info(f"MAC: {mac.hex(':')}")

            alarm = OPEN_CONNECTIONS.get(mac.hex(":"), None)
            if not alarm:
                writer.write(bytes([0xE4]))
                await writer.drain()
                return

            writer.write(bytes([0xE6, 0x0E]))
            await writer.drain()

            while True:
                command, data = await read_command(reader)
                logger.info(f"received: {command_to_str(command, data)}")

                with alarm[1].listener() as listener:
                    await send_command(alarm[0], command, data)
                    async with asyncio.timeout(5):
                        while True:
                            command_, data = await listener.get()
                            if command_ == command:
                                logger.info(
                                    f"sending: {command_to_str(command_, data)}"
                                )
                                await send_command(writer, command_, data)
                                break

        async def __downstream_alarm():
            logger = _logger.getChild("downstream_alarm")

            logger.info("sending MAC REQUEST")
            await send_command(writer, MAC_COMMAND)
            nonlocal mac
            command, mac = await read_command(reader)
            if command != MAC_COMMAND:
                raise Exception("Invalid data")
            logger.info(f"MAC: {mac.hex(':')}")

            logger.info("sending VERSION REQUEST")
            await send_command(writer, VERSION_COMMAND)
            nonlocal version
            command, version = await read_command(reader)
            if command != VERSION_COMMAND:
                raise Exception("Invalid data")
            logger.info(f"Version: {version}")

            command, data = await read_command(reader)
            if command != UNKNOWN_COMMAND:
                raise Exception("Invalid data")
            logger.info(f"Data: {data}")
            await send_command(
                writer,
                UNKNOWN_COMMAND,
                bytes.fromhex("24 08 07 03 17 30 47"),
            )

            OPEN_CONNECTIONS[mac.hex(":")] = (writer, receive)
            try:
                tg.create_task(__upstream())

                while True:
                    command, data = await read_command(reader)
                    logger.info(f"received: {command_to_str(command, data)}")
                    receive.emit((command, data))

                    logger.info("sending OK")
                    await send_command(writer, OK)
            finally:
                OPEN_CONNECTIONS.pop(mac.hex(":"))

        async def __downstream():
            logger = _logger.getChild("downstream")

            while True:
                command, data = await read_command(reader)
                logger.info(f"received {command_to_str(command, data)}")

                if command == XOR_COMMAND:
                    logger.info("sending 0x00 - no encryption")
                    await send_command(writer, 0x00)
                elif command == START_COMMAND:
                    logger.info("sending OK")
                    await send_command(writer, OK)

                    return await __downstream_alarm()
                elif command == CONNECTION_COMMAND:
                    return await __downstream_client(data)
                else:
                    raise Exception("Invalid data")

        async def __upstream():
            logger = _logger.getChild("upstream")

            while True:
                try:
                    u_reader, u_writer = await asyncio.open_connection(
                        "amt.intelbras.com.br", 9009
                    )
                    logger.info("connected")

                    logger.info("sending START")
                    await send_command(
                        u_writer,
                        START_COMMAND,
                        bytes.fromhex("45 12 12 52 57 19"),
                    )

                    command, _ = await read_command(u_reader)
                    if command != OK:
                        raise Exception("Invalid data")
                    logger.info("start ok received")

                    async def __ping():
                        while True:
                            await asyncio.sleep(30)
                            logger.info("sending PING")
                            await send_command(u_writer, PING_COMMAND)

                    async def __handle_push():
                        with receive.listener() as listener:
                            while True:
                                command, data = await listener.get()
                                if command == PUSH_COMMAND:
                                    logger.info(
                                        f"sending {command_to_str(command, data)}"
                                    )
                                    await send_command(u_writer, PUSH_COMMAND, data)

                    async def __handle_server():
                        while True:
                            command, data = await read_command(u_reader)
                            logger.info(f"received {command_to_str(command, data)}")

                            if command == OK:
                                continue
                            elif command == MAC_COMMAND:
                                response = mac
                            elif command == VERSION_COMMAND:
                                response = version
                            else:
                                logger.info(
                                    f"sending to client {command_to_str(command, data)}"
                                )
                                with receive.listener() as listener:
                                    await send_command(writer, command, data)
                                    while True:
                                        command_, data = await listener.get()
                                        if command_ == command:
                                            response = data
                                            break

                            logger.info(f"sending {command_to_str(command, response)}")
                            await send_command(u_writer, command, response)

                    async with asyncio.TaskGroup() as tg:
                        tg.create_task(__handle_push())
                        tg.create_task(__handle_server())
                        tg.create_task(__ping())

                except Exception:
                    logger.exception("error")

        tg.create_task(__downstream())


async def main():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s: %(message)s")

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    tasks: list[Task] = []

    async def handler(reader: StreamReader, writer: StreamWriter):
        task = asyncio.current_task()
        if task:
            tasks.append(task)
        await handle(logger, reader, writer)

    loop = asyncio.get_running_loop()
    task = asyncio.current_task()

    def cancel():
        nonlocal task
        if task:
            task.cancel()
        for task in tasks:
            task.cancel()

    loop.add_signal_handler(signal.SIGINT, cancel)
    loop.add_signal_handler(signal.SIGTERM, cancel)

    logger.info("Serving on 0.0.0.0:9009")
    server = await asyncio.start_server(handler, "0.0.0.0", 9009)
    await server.serve_forever()


if __name__ == "__main__":
    # msg = b"\x0c\xe9\x00\xf1\x00\x00\x00\x040\x03\x00Ip\xeb"

    # length = msg[0]
    # data = msg[1 : length + 1]
    # checksum_ = msg[length + 1]

    # expected_checksum = checksum(data)
    # byte = msg[11]

    # x = byte - 1
    # for i in range(0, 128, 10):
    #     cmd = bytes(
    #         [
    #             0x00,
    #             (((byte - 1) - i) + 128) % 128,
    #         ]
    #     )
    #     sync_data(0x39, cmd)
    #     print(f"Command: {cmd.hex(' ')}")

    # print(f"Message: {msg.hex(' ')}")
    # print(f"Length: {length:02x}")
    # print(f"Data: {data.hex(' ')}")
    # print(f"Checksum: {checksum_:02x}")
    # print(f"Expected checksum: {expected_checksum:02x}")
    # print(f"Byte: {byte:02x}")

    asyncio.run(main())
