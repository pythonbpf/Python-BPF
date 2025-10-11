# here, we will iterate through the dependencies and generate IR once dependencies are resolved fully
from .dependency_handler import DependencyHandler


class IRGenerator:
    def __init__(self, module, handler):
        self.module = module
        self.handler: DependencyHandler = handler
