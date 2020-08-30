# [Car Hacking 101](https://tryhackme.com/room/carhacking101)

## Bus CAN

Before CAN was originally developed by BOSCH in 1985 as an intra-vehicular communication system, automotive manufacturers used point-to-point wiring systems.

In simple terms, CAN allows various Electronic units in cars to communicate and share data with each other. The main motive of proposing CAN was that it allowed multiple ECU to be communicated with only a single wire.

>  A modern car can have as much as 70 ECUs. In a car, you can have components like Engine Control Unit, Airbags, Transmission, Gear Unit, Anti-lock braking system or simply ABS, infotainment systems, climate control, Windows, doors, etc. In order for all these units to communicate with each other, point-to-point wiring would have been so bulky. 

The CAN-Bus could be thought of as a noisy, crowded, slower version of Ethernet LAN except that the traffic is UDP rather than TCP.

> CAN is not only the communication protocol used in an automobile system

**Why CAN over another type of bus?**

The point to point wiring problem can be replaced with two wires, **CAN HIGH (CANH) and CAN LOW (CANL)** respectively. Now, this way communication is much faster, simpler and very easy to diagnose.

### CAN messages

A car can have multiple nodes that are able to send and/or receive messages. This message consists of essentially an ID, which is a priority of the message and also it can contain CAN message that can be of eight bytes or less at a time.

**Messages with numerically smaller value IDs are a higher priority and are always transmitted first.**

> Message from Brakes has a higher priority than a message from the audio player.

![CAN Data frame](https://www.picotech.com/images/uploads/library/topics/_med/CAN-full-frame.jpg)

CAN bus consists of two different wires. As it is a bus, multiple devices can be connected to these wires. **A CAN frame has 3 major parts**:

- **Arbitration Identifier**
- **Data Length Code**
- **Data field**


### Accessing CAN Bus in a real car

In order for you to access the CAN bus in your car, you need to have access to the **onboard diagnostic** port, aka **OBD**. Basically all the cars these days use **OBD-II**. 

> This is exactly what your car mechanics usees to identify the faults in your car. 

Locating OBD-II is pretty easy. This is located somewhere near the passenger’s seat or driver’s seat. And this should be accessible without the need of a screwdriver. This is how exactly an OBD looks like:

![OBD](https://sf1.viepratique.fr/wp-content/uploads/sites/9/2016/07/okport-obd.jpg)

![OBD Pinout](https://miro.medium.com/max/700/0*Dbf9ajPCxyByDQ7h)

#### HW

In order to a computer to talk directly with CAN, we need a USB to CAN cable.

![USB2CAn](https://www.8devices.com/media/banner.png)

You can come across with **Macchina M2** which is an opensource automotive interface that allows you to communicate to the CAN bus via OBD-II. Macchina M2 is that it is modular, meaning you can add WiFi, GSM, LTE, BLE modules on top of it.

![M2](https://www.macchina.cc/sites/default/files/styles/640_wide/public/connectable.png?itok=krFA_e3W)

There is also the **CLX000** from CSS Electronics, which lets you log and stream CAN data for e.g. car hacking purposes. More on this page: [CAN Bus Sniffer - Reverse Engineering Vehicle Data (Wireshark)](https://www.csselectronics.com/screen/page/reverse-engineering-can-bus-messages-with-wireshark/language/en)

> Data can be visualized in the free open-source Wireshark software and a plugin enables useful reverse engineering functionality.

![CLX000](https://canlogger1000.csselectronics.com/img/CLX000-Series-CAN-Loggers.jpg)

#### SW

To send and receive CAN packets, encode and/or decode them, on **Linux** you can check `SocketCAN`, `can-utils`, `vcan` and obviously, if you don't want to harm your car:  [ICSim](https://github.com/zombieCraig/ICSim).

The `can-utils` consist of 5 main tools:

- `cansniffer` for sniffing the packets.
- `cansend` for writing a packet.
- `candump` dump all received packets.
- `canplayer` to replay CAN packets.
- `cangen` to generate random CAN packets.
___



## Ressources

- [Car Hacker's Handbook by OpenGarages](http://opengarages.org/handbook/)
- [CAN Bus Sniffer - Reverse Engineering Vehicle Data (Wireshark)](https://www.csselectronics.com/screen/page/reverse-engineering-can-bus-messages-with-wireshark/language/en)
- [ICSim by zombieCraig](https://github.com/zombieCraig/ICSim)
- [Car Hacking 101: Practical Guide to Exploiting CAN-Bus using Instrument Cluster Simulator — Part I: Setting Up](https://medium.com/@yogeshojha/car-hacking-101-practical-guide-to-exploiting-can-bus-using-instrument-cluster-simulator-part-i-cd88d3eb4a53)
- [Car Hacking 101: Practical Guide to Exploiting CAN-Bus using Instrument Cluster Simulator — Part II: Exploitation](https://medium.com/@yogeshojha/car-hacking-101-practical-guide-to-exploiting-can-bus-using-instrument-cluster-simulator-part-ee998570758)
- [Car Hacking 101: Practical Guide to Exploiting CAN-Bus using Instrument Cluster Simulator — Part III: SavvyCAN, Fuzzing CAN Frame and playing around with CAN frames](https://medium.com/@yogeshojha/car-hacking-101-practical-guide-to-exploiting-can-bus-using-instrument-cluster-simulator-part-ea40c05c49cd)