#!/usr/bin/env python3
import time
from abc import ABC, abstractmethod





class Output(ABC): 
    def __init__(self,subject):
        subject.register(self)

    def update(self, *args, **kwargs):
        pass 



class OutputToScreen(Output): 



    super().__init__(subject)
    self._frame = None
    self._display_data = display_data 
    self._initialize()

    def _initialize() -> None: 
