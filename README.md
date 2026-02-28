# SSH Over Lossy Link (ssh-oll)

This project is for making SSH connections usable when making a connection with a server when there is high packet loss.  In the ideal case where you have full control over a server and its networking interfaces, using a project such as [Mosh](https://mosh.org/), or where instead of using a TCP based connection, a UDP based connection is used, allowing for dropped packet to not delay the connection.  However, when a server is behind a firewall or requires an SSH [ProxyJump](https://man.openbsd.org/ssh_config#ProxyJump) to access, using a UDP based connection is not an option.

Ssh-oll solves this problem, by layering a single ssh connecting over several "carrier ssh connections".  Each TCP connection is subject to individual packet loss, and there a single TCP connection can become delayed when a packet is loss.  However, by having multiple TCP connections,

## Setup

Install `ssh-oll` on both the client and the server.
```
git clone ...
make && make install
```
Then configure your `~/.ssh/config` as follows:
```
Host lossy-ssh-connection
    HostName ip/hostname of remote ssh host

Host good-ssh-connection
    ProxyCommand ssh-oll lossy-ssh-connection
```


## Command line
```
ssh-oll   [command line options]   lossy-ssh-host   [hostname on remote (default localhost)]   [remote port (default 22)]

--auto / --no-auto            Automattically adapt the number of carrier ssh connections and how the redudancy transmission rates. Default on
--path-on-server              Path to the ssh-oll binary on the server.  Default to "ssh-oll" with the binary being installed into the user's path.
--connections [N]             How many carrier ssh connections to open initially.  Default 10
--max-connections [N]         Max number of carrier connections that can be opened.  Default 200
--packet-size [N]             The max bytes of a single "packet" sent across a connection.  Default 800
--small-packet-redudancy [N]  For buffered data smaller than packet-size, send N copies of the data without using reed-solomon erasure coding. Default 2
--rs-redudancy [N]            Number of extra packets to send when using reed-solomon as a fraction.  Default 0.2
--max-delay [N]               Max delay in ms for sending data while waiting to see if buffer fills up for reed-solomon.  Default 1ms
--server                      Used to start the server instance of ssh-oll.  Default off, with starting the client instance of ssh-oll
```


## How it works

When `ssh-oll` is started, it opens a connection to the ssh host to launch the server session using the command `ssh lossy-ssh-host "ssh-oll --server localhost 22"`.  The server will create a unix socket such as `/tmp/ssh-oll-server.abc123def` with permissions set so that only the current user is able to access the server.  The server print the name of the socket out, and the daemonize itself, closing the initial ssh connection.  The `ssh-oll` client will then open several connections to the host using commands such as `ssh -L /tmp/ssh-oll-client.hgi456789/0:/tmp/ssh-oll-server.abc123def lossy-ssh-host`,  `ssh -L /tmp/ssh-oll-client.hgi456789/1:/tmp/ssh-oll-server.abc123def lossy-ssh-host`, . . ., `ssh -L /tmp/ssh-oll-client.hgi456789/10:/tmp/ssh-oll-server.abc123def lossy-ssh-host`.  The client can open up to `max-connection` number of ssh sessions, and by default the number of sessions will be dynamically determined by the client depending on the amount of packet loss.  The client is responsible for managing the number of connections and monitoring the health of each connection using ping packets.  To be efficient, the server and the client are both written as single threaded applications using epoll to manage the connections and sub processes.


```
enum packet_kind_e : uint8_t {
    PACKET_PING = 0,
    PACKET_PONG = 1,
    PACKET_SMALL = 2,
    PACKET_REED_SOLOMON = 3,
    PACKET_SET_CONFIG = 4,
    PACKET_START_CONNECTION = 5,
};
struct __attribute__((__packed__)) packet_header {
    uint64_t id;
    packet_kind_e packet_kind;
};

struct __attribute__((__packed__))  packet_small : packet_header {
    uint16_t size;
    uint8_t data[];
};

struct __attribute__((__packed__)) packet_reed_solomon : packet_header {
    uint16_t size;
    uint8_t n, k; // reed solomon meta data
    uint8_t data[]; // encoded data
};
struct __attribute__((__packed__)) packet_config : packet_header {
    // used by the client to configure redudancy transmission settings on the server
    uint16_t packet_size;
    uint16_t small_packet_redudancy;
    float max_delay_ms;
    float reed_solomon_redudancy;
    // other fields as needed
};

```
