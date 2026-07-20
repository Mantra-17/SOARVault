# ingestion/__init__.py
"""
SOARVault Ingestion Package
---------------------------
Exposes the primary public surface of the ingestion layer:

  - ``NormalizedAlert``    – canonical alert data model
  - ``PayloadNormalizer``  – raw SIEM payload → NormalizedAlert
  - ``IoCExtractor``       – extract IoCs from free-form text or dicts
  - ``Severity``           – severity enum  (CRITICAL / HIGH / MEDIUM / LOW / INFO)
  - ``AlertType``          – alert-type enum
  - ``AlertStatus``        – lifecycle state enum
"""

from .schema import (
    AlertStatus,
    AlertType,
    EnrichmentData,
    HostContext,
    IoC,
    NetworkContext,
    NormalizedAlert,
    Severity,
)
from .normalizer import IoCExtractor, PayloadNormalizer

__all__ = [
    # schema
    "NormalizedAlert",
    "IoC",
    "NetworkContext",
    "HostContext",
    "EnrichmentData",
    "Severity",
    "AlertType",
    "AlertStatus",
    # normalizer
    "PayloadNormalizer",
    "IoCExtractor",
]
