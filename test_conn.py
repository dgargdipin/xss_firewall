from connection import Connection
controller=Connection('127.0.0.1',8000)
# controller.block("10.0.0.1")
controller.block("192.168.0.1")
controller.get_flow_entries()
controller.block("192.168.0.2")
controller.get_flow_entries()