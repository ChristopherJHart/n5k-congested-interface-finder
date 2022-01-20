# Nexus 5500 Congested Interface Finder

This script attempts to identify a congested egress interface on a Nexus 5500 series switch based on intermittently-incrementing input discard counters on a user-defined interface.

## Motivation

Nexus 5000, 6000, and 7000 switches utilize a Virtual Output Queue (VOQ) architecture for unicast
traffic. This means that when a packet enters the switch, the switch does the following:

1. Parses the packet's headers.
2. Makes a forwarding decision on the packet, thus determining the packet's egress interface.
3. Buffers the packet in memory on the ingress interface within a virtual queue until the egress interface can transmit the packet.

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
egress interfaces on Nexus 5500 series switches.

## Requirements/Prerequisites

This script has the following requirements:

* Must be executed using Python 3.8 or higher.
* Must have SSH connectivity from the host on which this script is executed to the Nexus 5500 series switch being analyzed.
* Input discards must intermittently increment on a specific interface. If input discards "move" from one interface to another each time the intermittent network congestion begins, this script will not be helpful (although it can be easily modified to accommodate this scenario.)

## Usage

This script can be used as shown below:

```shell
python n5k_congested_interface_finder.py {switch-ip-address} {interface-name} [--username switch-username] [--password switch-password] [--debug]
```

Parameters include:

* **switch-ip-address** - The IP address of the Nexus switch you would like to monitor. An FQDN (Fully-Qualified Domain Name) can also be used.
* **interface-name** - The name of the physical (e.g. Ethernet1/1) or logical (e.g. port-channel1) interface to monitor for input discards.
* **switch-username** - The username that should be used to access the Nexus switch. For most Nexus switches in CX Labs, the default username of `admin` is used.
* **switch-password** - The password that should be used to access the Nexus switch. For most Nexus switches in CX Labs, the default password of `cisco!123` is used. Note that the `!` in `cisco!123` needs to be escaped in most shells, so it should be `cisco\!123` instead.
* **debug** - Enables debug logging for troubleshooting purposes. Not recommended for production use.

This script will run in an infinite loop while it's collecting data. After you're positive you have collected some quality data, view the results by pressing Control+C. A full report of gathered data and top egress interface talkers (which suggest the interfaces that most often had data in their respective virtual queues during times of network congestion) will be shown. An example is below:

```
$ python n5k_congested_interface_finder.py 192.0.2.10 Ethernet1/31 --username admin --password Password\!123
Connecting to device '192.0.2.10' with username 'admin'...
Successfully connected to device!
[2022-01-19 17:54:12.358728] Checking for input discards on interface Ethernet1/31...
[2022-01-19 17:54:12.358728] 71915 new input discards found on Ethernet1/31, 1 ASIC registers!
[2022-01-19 17:54:14.702041] Checking for input discards on interface Ethernet1/31...
[2022-01-19 17:54:14.702041] 1748955 new input discards found on Ethernet1/31, 1 ASIC registers!
[2022-01-19 17:54:17.081937] Checking for input discards on interface Ethernet1/31...
[2022-01-19 17:54:17.081937] 2523546 new input discards found on Ethernet1/31, 1 ASIC registers!
[2022-01-19 17:54:20.453788] Checking for input discards on interface Ethernet1/31...
[2022-01-19 17:54:20.453788] 1749266 new input discards found on Ethernet1/31, 1 ASIC registers!
[2022-01-19 17:54:22.772208] Checking for input discards on interface Ethernet1/31...
^C
Raw results:

2022-01-19 17:54:12.358728: 2212147758 input discards (+71915)
    Ethernet1/10 (S0A1 0): 206
2022-01-19 17:54:14.702041: 2213896713 input discards (+1748955)
    Ethernet1/10 (S0A1 0): 197
2022-01-19 17:54:17.081937: 2216420259 input discards (+2523546)
    Ethernet1/10 (S0A1 0): 202
2022-01-19 17:54:20.453788: 2218169525 input discards (+1749266)
    Ethernet1/10 (S0A1 0): 198

Top Talkers:
Ethernet1/10 (S0A1 0): 803
```

This output *suggests* that Ethernet1/10 is the congested egress interface. This does *not* 100% confirm that Ethernet1/10 is the congested egress interface, but it does provide solid data suggesting that Ethernet1/10 *could* be the congested egress interface.

## Installation

This script can be installed using the instructions below:

1. Clone this repository to your workstation of choice.

```shell
git clone https://github.com/ChristopherJHart/n5k-congested-interface-finder
```

2. Move into the newly-created directory.

```shell
cd n5k-congested-interface-finder
```

3. Create and activate a virtual environment to house the script's dependencies.

```shell
python -m venv venv; source venv/bin/activate
```

4. Install the script's dependencies using `pip`:

```shell
pip install -r requirements.txt
```

5. Execute the script. The example below monitors for input discards on interface Ethernet1/1 of a switch reachable at 192.0.2.100 with a username of `admin` and a password of `cisco!123`.

```shell
python n5k_congested_interface_finder.py 192.0.2.100 Ethernet1/1
```

To define a username and password in the script's arguments, use the `--username` and `--password` parameters as shown below. Note the escaped password due to the exclamation mark in the password.

```shell
python nxos_push_config.py 192.0.2.100 Ethernet1/1 --username admin --password ExamplePassword\!123
```

Refer to the Usage section of this document for more information on how to use this script.
