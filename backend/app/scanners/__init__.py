from typing import List, Dict, Optional
from app.scanners.base import BaseScanner
from app.models.scan import ScanMode
from app.scanners.passive.headers import SecurityHeadersScanner
from app.scanners.passive.cookies import CookieSecurityScanner
from app.scanners.passive.tls_config import TLSConfigurationScanner
from app.scanners.passive.info_disclosure import InformationDisclosureScanner
from app.scanners.passive.dependencies import DependencyAuditorScanner
from app.scanners.active.http_methods import HTTPMethodsScanner
from app.scanners.active.cors_analyzer import CORSAnalyzerScanner
from app.scanners.active.input_boundary import InputBoundaryScanner
from app.scanners.active.auth_config import AuthConfigScanner
from app.scanners.lab.lab_simulation import LocalLabSimulationScanner

ALL_SCANNERS: List[BaseScanner] = [
    # Passive
    SecurityHeadersScanner(),
    CookieSecurityScanner(),
    TLSConfigurationScanner(),
    InformationDisclosureScanner(),
    DependencyAuditorScanner(),
    # Safe Active
    HTTPMethodsScanner(),
    CORSAnalyzerScanner(),
    InputBoundaryScanner(),
    AuthConfigScanner(),
    # Lab Simulation
    LocalLabSimulationScanner(),
]

SCANNER_MAP: Dict[str, BaseScanner] = {s.id: s for s in ALL_SCANNERS}


def get_scanners_for_mode(
    scan_mode: str, selected_modules: Optional[List[str]] = None
) -> List[BaseScanner]:
    active_scanners: List[BaseScanner] = []

    if scan_mode == ScanMode.PASSIVE:
        # Passive analysis only
        active_scanners = [s for s in ALL_SCANNERS if s.id.startswith("passive_")]
    elif scan_mode == ScanMode.SAFE_ACTIVE:
        # Passive + Safe active
        active_scanners = [
            s for s in ALL_SCANNERS if s.id.startswith("passive_") or s.id.startswith("active_")
        ]
    elif scan_mode == ScanMode.LAB_SIMULATION:
        # All scanners including local lab simulator
        active_scanners = list(ALL_SCANNERS)

    if selected_modules:
        active_scanners = [s for s in active_scanners if s.id in selected_modules]

    return active_scanners
