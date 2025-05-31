"""
Chaincraft - A platform for blockchain education and prototyping.

This package provides the fundamental components needed to create distributed networks,
implement consensus mechanisms, and prototype blockchain applications.
"""

__version__ = "0.4.1"
__author__ = "Chaincraft Contributors"
__email__ = "chaincraft@example.com"

from .node import ChaincraftNode
from .shared_object import SharedObject, SharedObjectException
from .shared_message import SharedMessage
from .index_helper import IndexHelper
from . import crypto_primitives

__all__ = [
    "ChaincraftNode",
    "SharedObject",
    "SharedObjectException",
    "SharedMessage",
    "IndexHelper",
    "crypto_primitives",
    "__version__",
]
