class TamperService:
    def __init__(self):
        self.armed: bool = False

    def is_armed(self) -> bool:
        return self.armed

    def arm(self) -> None:
        self.armed = True

    def disarm(self) -> None:
        self.armed = False


tamper_service = TamperService()

