## python-can-zlgcan



This socketcand server is a for socketcand that lets you use [ZLG CAN adapters](https://github.com/deansay/python-can-zlgcan) with the [ZLG CAN windows 32 Driver](https://manual.zlg.cn/web/#/146) in python-can.

* Support CAN/CANFD

### Installation

Install using pip:

    $ pip install python-can-zlgcan   #not support yet.


### Usage

Overall, using this server is quite similar to the main Python-CAN library, with the interface named `socketcand`. To integrate the socketcand interface into your scripts, you can use python-can-zlgcan as a server. For most scenarios, incorporating a socketcand interface is as easy as modifying Python-CAN examples with the lines provided below:


Create python-can bus with the Canine USB interface:

    import can
    can.interface.Bus(interface='socketcand', host='127.0.0.1', port=12346, channel='can0 4 0')

