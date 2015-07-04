FGRE 2015
=========

Supplementary material for workshop on OF1.0 HW and POX controller

Setting up a working environment
--------------------------------

1. Log in to your virtual machine. Access with the user that created the VMs.
    
    ```
    # Your_User is the user ID that created the machine
    # This ID is used to access the VM via public keys

    # Returned_IP is the IP of each VM that was returned to you after being created
    ssh <your_user>@<returned_ip>
    ```
1. Update your environment
    
    ```
    apt-get update
    ```
1. Install some packets
    
    ```
    apt-get install vlan git vim -y
    ```
1. Configure the interfaces of both sender/controller and receiver machines:
    
    ```
    # X is the interface of the VM that is connected to the dpid
    ifconfig eth<X> up
    
    # VLAN is the VLAN ID you have used when defining your flow rules
    vconfig add eth<X> <vlan> 
    ifconfig eth<X>.<vlan> up
    
    # Chosen_IP is an IP of your choice, used to easily ping between VMs
    # Note that you should use IPs within the same subnet to ping the two machines
    ifconfig eth<X>.<vlan> <chosen_ip>
    ```
1. Move to your user folder and clone the repository:
    
    ```
    cd ~
    git clone https://github.com/CarolinaFernandez/fgre2015.git
    ```
1. Run the controller in the sender/controller machine. By default, the controller will run in `reactive` behaviour (responding to missed packets). You may add the `--proactive` argument to see how it behaves `proactive`ly (inserting rules at the beginning).
        
    ```
    cd ~/fgre2015/pox
    # Reactive behaviour
    python pox.py log.level --DEBUG forwarding.l2_fgre
    # Proactive behaviour
    python pox.py log.level --DEBUG forwarding.l2_fgre --proactive
    ```
  
