"""Attempt to identify a congested egress interface based on input discards on a given interface.

Nexus 5000, 6000, and 7000 switches utilize a Virtual Output Queue (VOQ) architecture for unicast
traffic. This means that when a packet enters the switch, the switch does the following:

1. Parses the packet's headers.
2. Makes a forwarding decision on the packet, thus determining the packet's egress interface.
3. Buffers the packet in memory on the ingress interface within a virtual queue until the egress
   interface can transmit the packet.

When a specific egress interface is congested (meaning, the total sum of traffic that needs to be
transmitted out of the interface exceeds the bandwidth of the interface itself), the buffers of the
ingress interface will begin to fill with data. If this happens over a "long" period of time, then
the ingress interface's buffer will become full, and no additional packets can be stored in the
buffer. Additional packets are then dropped on ingress, and the "input discards" counter is
incremented on the ingress interface.

The word "long" is purposefully ambiguous because it is subjective. Within a matter of
milliseconds, an egress interface can become congested, ingress buffers can fill, and input
discards can begin to increment on a switch's interfaces. A few milliseconds is a very short amount
of time to a human being, but to a computer, a few milliseconds can be a lifetime.

Nexus 5500 series switches offer a command - `show hardware internal carmel asic <x> registers
match .*STA.*frh.*` - that can identify the amount of data stored in a specific egress interface's
virtual queue at the time of the command's execution. This command is useful when network
congestion is constantly occurring (meaning, input discards are constantly incrementing on one or
more interfaces), but is not very useful when network congestion is intermittent and strikes over a 
small period of time.

This script is designed to assist network operators with identifying intermittently-congested
egress interfaces on Nexus 5500 series switches. This script has the following requirements:

- Must be executed using Python 3.8 or higher.
- Must have SSH connectivity from the host on which this script is executed to the Nexus 5500
  series switch being analyzed.
- Input discards must intermittently increment on a specific interface. If input discards "move"
  from one interface to another each time the intermittent network congestion begins, this script
  will not be helpful (although it can be easily modified to accommodate this scenario.)
"""

from typing import Optional, List
from datetime import datetime
import re
import argparse
import logging
import sys
import asyncio
from getpass import getpass
from scrapli.driver.core.cisco_nxos import AsyncNXOSDriver
from rich.console import Console


__author__ = "Christopher Hart"
__email__ = "chart2@cisco.com"
__copyright__ = "Copyright (c) 2022 Cisco Systems. All rights reserved."
__credits__ = [
    "Christopher Hart",
]
__license__ = """
################################################################################
# Copyright (c) 2022 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.
################################################################################
"""
__version__ = "0.0.1"

parser = argparse.ArgumentParser(
    description=(
        "Identifies congested egress interfaces on a Nexus 5500 switch based on incrementing input "
        "discards on a user-specified interface."
    )
)

# Required argument
parser.add_argument(
    "ip", metavar="ip/fqdn", help="IP or FQDN of Nexus 5500 switch", action="store"
)
parser.add_argument(
    "interface",
    metavar="interface",
    help="Interface to monitor for input discards",
    action="store",
)

# Optional arguments
parser.add_argument("--debug", "-d", help="Enable debug logging", action="store_true")
parser.add_argument(
    "--username",
    "-u",
    metavar="admin",
    help="Username to log into Nexus switch",
    action="store",
)
parser.add_argument(
    "--password",
    "-p",
    metavar="cisco!123",
    help="Password to log into Nexus switch",
    action="store",
)

args = parser.parse_args()

if args.debug:
    logging.basicConfig(
        filename="n5k_congested_interface_finder.log",
        level=logging.DEBUG,
        format="%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s",
    )
else:
    logging.basicConfig(
        filename="n5k_congested_interface_finder.log",
        level=logging.INFO,
        format="%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s",
    )
    logging.getLogger("scrapli").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

console = Console()


async def command(conn: AsyncNXOSDriver, command: str) -> str:
    """Get output of show command from switch.

    Args:
        conn (AsyncNXOSDriver): Scrapli driver representing the connection to the Nexus switch.
        command (str): Command to execute on switch.

    Returns:
        str: The output of `command` executed on the switch using `conn`.
    """
    response = await conn.send_command(command)
    response.raise_for_status()
    return response.result


def parse_interface_input_discards(cli_output: str) -> int:
    """Parses the number of input discards on an interface based on raw CLI output.

    The raw CLI output of the "show interface <interface-name> | include input.discard" command
    looks similar to this:

        0 input with dribble  461851 input discard

    This function uses a regular expression pattern to extract the integer number of input discards
    from this CLI output.
    """
    discard_pattern = re.compile(r"^\s+.*?(?P<discards>\d+)\s+input\s+discard")
    discard_match = discard_pattern.search(cli_output)
    if discard_match:
        discards = int(discard_match.groupdict().get("discards", 0))
        logger.debug("Input discards: %s", discards)
        return discards
    # We should always match on the above regular expression pattern. If we don't, log a warning
    # and return 0.
    #
    # This issue has not been encountered in testing, but best to be explicit and safe just in
    # case.
    logger.warning("Failed to find input discards counter in CLI")
    return 0


async def get_input_discards(
    conn: AsyncNXOSDriver, interface_name: str, previous_discards: int
) -> dict:
    """Retrieve, parse, and return structured data about interface input discards.

    This command executes the "show interface <interface-name> | include input.discard" command on
    the Nexus 5500 series switch using an existing SSH connection. This command is purposefully
    filtered using the "include" command for speed/efficiency purposes; it is faster to let the
    NX-OS CLI filter our output for us than to do the same thing within Python.

    The previous quantity of input discards detected on this interface is also passed into this
    function so that we can compute how many input discards were seen between this execution
    of the command and the previous execution of the command. This information is returned through
    the "discards_delta" key-value pair.
    """
    raw_output = await command(
        conn, f"show interface {interface_name} | include input.discard"
    )
    current_discards = parse_interface_input_discards(raw_output)
    return {
        "interface": interface_name,
        "current_discards": current_discards,
        "previous_discards": previous_discards,
        "discards_delta": current_discards - previous_discards,
    }


def parse_asic_registers(cli_output: str) -> List[dict]:
    """Parses relevant Nexus 5500 ASIC registers based on raw CLI output.

    The raw CLI output of the "show hardware internal carmel asic <x> registers match .*STA.*frh.*"
    command looks similar to this:

    Slot 0 Carmel 0 register contents:
    Register Name                                          | Offset   | Value
    -------------------------------------------------------+----------+-----------
    car_bm_STA_frh0_addr_0                                 | 0x5031c  | 0
    car_bm_STA_frh0_addr_1                                 | 0x5231c  | 0
    car_bm_STA_frh0_addr_2                                 | 0x5431c  | 0
    car_bm_STA_frh0_addr_3                                 | 0x5631c  | 0
    car_bm_STA_frh0_addr_4                                 | 0x5831c  | 0
    car_bm_STA_frh0_addr_5                                 | 0x5a31c  | 0x4

    The command we execute removes all registers that have a value of "0", so the output this
    function parses will look similar to this:

    Slot 0 Carmel 0 register contents:
    Register Name                                          | Offset   | Value
    -------------------------------------------------------+----------+-----------
    car_bm_STA_frh0_addr_5                                 | 0x5a31c  | 0x4

    This function uses a regular expression pattern to to extract the address of each register (the
    "5" in the "car_bm_STA_frh0_addr_5" register name) as well as the value ("0x4" in the output
    above).

    Each individual register matching the regular expression pattern is appended to a list, which
    is ultimately return.
    """
    results = []
    congestion_register_pattern = re.compile(
        r"^car_bm_STA_frh_eg_addr_(?P<address>\d+)\s+\|\s+\S+\s+\|\s+(?P<value>\S+)"
    )
    for line in cli_output.splitlines():
        match = congestion_register_pattern.search(line)
        if match:
            results.append(match.groupdict())
    return results


async def get_asic_registers(conn: AsyncNXOSDriver, mappings: List[dict]) -> List[dict]:
    """Retrieve, parse, and return structured data about ASIC registers.

    This command executes the "show hardware internal carmel asic <x> registers match
    .*STA.*frh.* | exclude '| 0$'" command on the Nexus 5500 series switch using an existing SSH
    connection. This command is purposefully filtered using the "include" command for
    speed/efficiency purposes; it is faster to let the NX-OS CLI filter our output for us than to
    do the same thing within Python.

    To accurately identify congested egress interfaces, this command needs to be executed on each
    ASIC of the Nexus switch. There are up to 13 ASICs on any given Nexus 5500 series switch, so
    this command is executed for each ASIC (regardless of whether they exist or not).

    The slot and ASIC number of each ASIC register found in this command is added to the structured
    data returned by this function. Additionally, the hexadecimal value is translated to an integer
    for ease of use. Finally, the human-friendly interface name (e.g. "Ethernet1/1") that the ASIC
    and address translate to is appended to the results.
    """
    results = []
    for asic_id in range(0, 14):  # Hard-coding ASIC IDs, this is bad, but oh well.
        raw_output = await command(
            conn,
            f"show hardware internal carmel asic {asic_id} registers match .*STA.*frh.* | exclude '| 0$'",
        )
        parsed_results = parse_asic_registers(raw_output)
        for r in parsed_results:
            r["slot"] = 0
            r["asic"] = asic_id
            r["value"] = int(r.get("value"), 16)
            r["address"] = int(r.get("address"))
            r["interface"] = convert_asic_mac_to_interface(
                mappings, r["asic"], r["address"]
            )
        results += parsed_results
    return results


def parse_asic_mac_interface_mappings(cli_output: str) -> List[dict]:
    """Parse the ASIC/MAC/interface mappings of the switch.

    Parses the raw CLI output of the "show hardware internal carmel all-ports" command using a
    regular expression pattern to extract the interface numbering associated with each ASIC/MAC
    tuple.
    """
    pattern = re.compile(
        r"^\S+(?P<interface>\d+\/\d+)\s*\|\d+\s*\|(?P<asic>\d+)\s*\|(?P<mac>\d+)"
    )
    results = []
    for line in cli_output.splitlines():
        match = pattern.search(line)
        if match:
            d = match.groupdict()
            results.append(
                {
                    "interface": d.get("interface"),
                    "asic": int(d.get("asic")),
                    "mac": int(d.get("mac")),
                }
            )
    return results


async def get_asic_mac_interface_mappings(conn: AsyncNXOSDriver) -> List[dict]:
    """Get and parse the ASIC/MAC/interface mappings of the switch.

    Returns structured data representing how each ASIC/MAC tuple of the switch translates to the
    human-friendly interface numbering (e.g. "1/1") of the switch. This is used to clearly identify
    a congested egress interface using interface terms a network operator may be familiar with
    (e.g. "Ethernet1/1") instead of the slot/ASIC/MAC tuple used internally by NX-OS (e.g. "Slot 0,
    ASIC 2, MAC 5")
    """
    raw_output = await command(conn, "show hardware internal carmel all-ports")
    return parse_asic_mac_interface_mappings(raw_output)


async def main(results: List[dict]) -> None:
    """Main driver function for the script.

    This function does the following:

    1. Connects to the switch via SSH using user-provided username and password.
    2. Fetch ASIC/MAC interface mappings
    3. Fetch current input discards on user-provided interface
    4. Infinite loop that identifies when input discards are incrementing on the user-provided
       interface, which signifies that an egress interface is currently congested. Under this
       condition, fetches ASIC registers that indicate which specific virtual queues corresponding
       with specific egress interfaces have data in them.
    5. Add relevant ASIC register data to the "results" list.
    """
    if not args.username:
        args.username = input(f"Enter username to log into Nexus switch {args.ip}: ")
    if not args.password:
        args.password = getpass(
            f"Enter password for user account {args.username} to log into Nexus switch {args.ip}: "
        )
    logger.info("Connecting to device %s with username %s", args.ip, args.username)
    console.print(
        f"Connecting to device '{args.ip}' with username '{args.username}'...",
        style="cyan",
    )
    async with AsyncNXOSDriver(
        transport="asyncssh",
        host=args.ip,
        auth_username=args.username,
        auth_password=args.password,
        auth_strict_key=False,
    ) as conn:
        logger.info("Connected to device")
        console.print("Successfully connected to device!", style="green")
        await conn.send_command("terminal dont-ask")
        # Get current discard counter
        data = await get_input_discards(conn, args.interface, 0)
        current_discards = data.get("current_discards")
        # Get ASIC/MAC-to-interface mappings
        interface_mappings = await get_asic_mac_interface_mappings(conn)
        while True:
            now = datetime.now()
            console.print(
                f"[{now}] Checking for input discards on interface {args.interface}...",
                style="cyan",
                highlight=False,
            )
            discards_data = await get_input_discards(
                conn, args.interface, current_discards
            )
            if discards_data.get("discards_delta"):
                current_discards = discards_data.get("current_discards")
                registers = await get_asic_registers(conn, interface_mappings)
                console.print(
                    f"[{now}] {discards_data.get('discards_delta')} new input discards found on {args.interface}, {len(registers)} ASIC registers!",
                    style="red",
                )
                results.append(
                    {
                        "timestamp": now,
                        "registers": registers,
                        "discards": current_discards,
                        "discards_delta": discards_data.get("discards_delta"),
                    }
                )


def convert_asic_mac_to_interface(
    mappings: List[dict], asic: int, mac: int
) -> Optional[str]:
    """Given an ASIC/MAC tuple, fetch the relevant human-friendly interface numbering."""
    for mapping in mappings:
        if mapping.get("asic") == asic and mapping.get("mac") == mac:
            return mapping.get("interface")


if __name__ == "__main__":
    try:
        results = []
        asyncio.run(main(results))
    except KeyboardInterrupt:
        # Control+C to break out of infinite loop and print results.
        console.print("")
        if results:
            console.print("Raw results:")
            console.print("")
            for result in results:
                console.print(
                    f"{result.get('timestamp')}: {result.get('discards')} input discards (+{result.get('discards_delta')})"
                )
                for register in result.get("registers"):
                    console.print(
                        f"    Ethernet{register.get('interface')} (S{register.get('slot')}A{register.get('asic')} {register.get('address')}): {register.get('value')}"
                    )
            console.print("")
            console.print("Top Talkers:")
            talkers = {}
            for result in results:
                for r in result.get("registers"):
                    identifier = f"Ethernet{r.get('interface')} (S{r.get('slot')}A{r.get('asic')} {r.get('address')})"
                    talkers[identifier] = r.get("value") + talkers.get(identifier, 0)
            for k in sorted(talkers.items(), key=lambda x: x[1], reverse=True):
                console.print(f"{k[0]}: {k[1]}")
        else:
            console.print(
                f"Input discards on interface {args.interface} did not increment during script's execution, so no register data was collected.",
                style="red",
                highlight=False,
            )
        sys.exit()
