from enum import Enum, auto

class PacketDirection(Enum):
    """
    PacketDirection creates constants for the direction of the packets.
    There are two possible directions that the packets can follow.
    PacketDirection is an enumeration with the values automatically assigned:
    - FORWARD
    - BACKWARD
    """

    FORWARD = auto()
    BACKWARD = auto()
