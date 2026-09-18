from dataclasses import dataclass


@dataclass
class Check:
    category: str
    name: str
    status: str        # pass / warn / fail / info / unknown
    message: str
    weight: float = 0
    earned: float = 0
    applicable: bool = True
