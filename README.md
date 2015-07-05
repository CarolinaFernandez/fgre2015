# FGRE 2015

Supplementary material for workshop on OF1.0 HW and POX controller.

## Setting up a working environment

1. Log in to your virtual machine. Access with the user that created the VMs.
    
    ```
    # Your_User is the user ID that created the machine
    # This ID is used to access the VM via public keys

    # Returned_IP is the IP of each VM that was returned to you after being created
    ssh <your_user>@<returned_ip>
    ```
1. Update your environment
    
    ```
    sudo apt-get update
    ```
1. Install some packets
    
    ```
    sudo apt-get install vlan git vim -y
    ```
    
1. Move to your user folder and clone the repository:
    
    ```
    cd ~
    git clone https://github.com/CarolinaFernandez/fgre2015.git
    ```
    
1. Run the `set_up_host.sh` script to configure the machine:
    
    ```
    pwd=~/fgre2015/script
    # Log in as root to perform administrative tasks
    sudo -i
    cd $pwd
    # VLAN is the VLAN ID you have been granted and using for your experiment
    vlan=...
    # To configure the 'sender' host
    ./set_up_host.sh sender $vlan
    # To configure the 'receiver' host
    ./set_up_host.sh receiver $vlan
    # Exit root
    exit
    ```
    This script declares a new sub-interface with the granted VLAN, and assigns the following IPs:
    * _Sender_: 192.161.24.29
    * _Receiver_: 192.161.24.30

## Running the controllers

For the following examples, you will be using two machines:
  * _sender_: same machine used for the controller will be used to transmit traffic
  * _receiver_: another machine, typically used to receive traffic
And a number of physical switches (_datapaths_)

### L2 learning

This is one of the built-in POX applications. It detects all connected datapaths and ports, and inserts rules to send traffic though the appropriate port (or either flood it through all but ingress port).

1. Run the controller in the sender/controller machine.
        
    ```
    cd ~/fgre2015/pox
    python pox.py log.level --DEBUG forwarding.l2_learning
    ```
    
1. In a new terminal in the _sender_ (here, also controller) host, ping _receiver_ (assigned IP: _192.161.24.30_):
    
    ```
    ping 192.161.24.30
    ```
    
    You will immediately see the response of the ping. In the terminal of the controller you should be able to see some initial flow insertion logs, followed by other messages -- mainly LLDP-related, TLV parsing failure, which you may ignore.

### Simple rule insertion

In this example, a controller has been developed to allow IP traffic between the _sender_ and _receiver_ machines. Specific rules are inserted to allow both outgoing (_sender > receiver_) and incoming (_receiver > sender_) traffic. The insertion of rules for this example is performed in a static way and traverses every switch of the physical topology.

1. Run the custom controller in the sender/controller machine. By default, the controller will run in _reactive_ behaviour (responding to missed packets), but you may set it to act in a _proactive_ manner (inserting rules at the beginning), via arguments.You shall set up the _VLAN_ ID you have been granted.
        
    ```
    cd ~/fgre2015/pox
    # VLAN is the VLAN ID you have been granted and are using for your experiment
    vlan=...
    # Reactive behaviour
    python pox.py log.level --DEBUG forwarding.fgre_topo --vlan=$vlan
    # Proactive behaviour
    python pox.py log.level --DEBUG forwarding.fgre_topo --proactive --vlan=$vlan
    ```
    
    **Important**: wait until all (five) used datapaths are found. If this does not happen in a reasonable time frame, restart the controller.
    
1. In a new terminal in the _sender_ (here, also controller) host, ping _receiver_ (assigned IP: _192.161.24.30_):
    
    ```
    ping 192.161.24.30
    ```
    
    After some seconds, you should be able to see the reply back from the _receiver_ host. In the controller terminal there should be something like this:
    
    ```
    [forwarding.fgre_topo  ] Receiving packet from dpid=3, in_port=1
    [forwarding.fgre_topo  ] Installing rule [dpid=3]: vlan=1798, in=1 <-> out=2
    ```

### Dummy firewall example

As with the previous example, a controller has been developed to also allow IP traffic between the _sender_ and _receiver_ machines. Now, traffic may be temporally blocked under certain network conditions which could be considered as _malicious_. Here, the condition is that the time between packets from a given machine and port do not exceed much the `threshold` value defined by the user (in seconds). For instance, for threshold=0.2, the controller would determine that a ping of frequency>threshold is okay; otherwise traffic will be blocked for 30 seconds by means of DROP rules insertion.

1. Run the custom controller in the sender/controller machine. This controller only runs in _reactive_ behaviour (responding to missed packets). You shall set up the _VLAN_ ID you have been granted and also a number/fraction of _threshold_ seconds before determining there's too much traffic going on through the internal network.
        
    ```
    cd ~/fgre2015/pox
    # VLAN is the VLAN ID you have been granted and are using for your experiment
    vlan=...
    # Threshold is the max. number of seconds allowed between packets
    threshold=...
    python pox.py log.level --DEBUG forwarding.fgre_fw --threshold=$threshold --vlan=$vlan
    ```
    
    **Important**: wait until all (five) used datapaths are found. If this does not happen in a reasonable time frame, restart the controller.
    
1. In a new terminal in the _sender_ (here, also controller) host, ping _receiver_ (assigned IP: _192.161.24.30_):
    
    ```
    ping 192.161.24.30 -i 1
    ```
    
    You may initially see a number of dropped packets, followed by a number of responses. This is the result of sending proper packet-out messages to allow outgoing (_sender > receiver_) and incoming (_receiver > sender_) traffic.

    If, at a given time, the frequency of traffic transmission is too high (for the previously configured `threshold` value), a DROP rule will be inserted in the switch and traffic will be blocked for 30 seconds. In the controller terminal you should see the packet-outs being send:    
    ```
    [forwarding.fgre_fw    ] Receiving packet from dpid=1, in_port=12
    [forwarding.fgre_fw    ] Sending packet-out [dpid=1]: vlan=1798, in=12 <-> out=3
    ```
    
1. Stop the previous ping, and adjust a new interval to be the same as the _threshold_:
    
    ```
    ping 192.161.24.30 -i $threshold
    ```
    
    You should see a similar output as in the previous ping, to be soon identified and blocked. If you look at the controller output, it should contain messages similar to:
    
    ```
    [forwarding.fgre_fw    ] Receiving packet from dpid=1, in_port=12
    [forwarding.fgre_fw    ] Installing DROP rule [dpid=1]: vlan=1798, in=12
    ```
