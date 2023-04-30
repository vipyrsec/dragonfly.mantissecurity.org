"""Model definitions"""

from pydantic.dataclasses import dataclass, Field


@dataclass(frozen=True)
class Error:
    """Returned when an error occurs"""

    detail: str


@dataclass(frozen=True)
class ServerMetadata:
    """Metadata about the server"""

    version: str
    server_commit: str
    rules_commit: str


@dataclass(frozen=True)
class PyPIPackage:
    """Incoming package data"""

    package_name: str
    package_version: str | None = Field(None)


@dataclass(frozen=True)
class MaliciousFile:
    """Represents a malicious file, which YARA rules it matched, and it's individual score"""

    file_name: str
    """Filename"""

    # Mapping of rule name to rule score
    rules: dict[str, int]

    def calculate_file_score(self) -> int:
        return sum(self.rules.values())


@dataclass(frozen=True)
class PackageAnalysisResults:
    """Results of analysing a PyPi package for malware"""

    malicious_files: list[MaliciousFile]

    def get_matched_rules(self) -> dict[str, int]:
        """Aggregate all of the matches rules and return the rule name mapped to it's weight"""
        rules: dict[str, int] = {}
        for file in self.malicious_files:
            for rule, weight in file.rules.items():
                rules[rule] = weight

        return rules

    def calculate_package_score(self) -> int:
        return sum(self.get_matched_rules().values())


@dataclass(frozen=True)
class PackageDistributionScanResults:
    """Results of the scan"""

    file_name: str
    inspector_url: str
    analysis: PackageAnalysisResults


@dataclass(frozen=True)
class HighestScoreDistribution:
    """Results of the scan"""

    score: int
    matches: list[str]
    most_malicious_file: str
    inspector_link: str


@dataclass(frozen=True)
class PackageScanResults:
    """Results of the scan"""

    name: str
    """Package name"""
    version: str
    """Version of the package that was checked"""
    pypi_link: str
    """Pypi link to the package itself"""
    distributions: list[PackageDistributionScanResults]
    """The distributions in the release"""
    highest_score_distribution: HighestScoreDistribution | None
    """Metadata for the highest scoring matches"""
