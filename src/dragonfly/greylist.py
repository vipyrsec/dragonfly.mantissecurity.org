import json
import sqlite3

from .packages import MaliciousFile
from .packages import PackageAnalysisResults

def greylist(package_name: str, analysis: PackageAnalysisResults) -> bool:
    """Check positive scan results against greylist

    Returns True if the report should be skipped; False otherwise.

    Returns False under the following conditions:
        package name not previously scanned.
        package has new files being reported as malicious
        package has new rules being triggered
        package's rule weights have increased from previous iteration
    """
    conn = sqlite3.connect("greylist.db")  # This is a temporary name until I query Rem
    cursor = conn.cursor()

    previous_scan = check_db(package_name)
    if previous_scan = "":
        return False

    previous_file_info = json.loads(previous_scan)
    current_file_info = {a.filename: a.rules for a in analysis.malicious_files}

    for file in current_file_info:
        if file not in previous_file_info:  # new file
            return False
        for rule in file:
            if rule not in previous_file_info[file]:  # new rule
                return False
            if current_file_info[file][rule] > previous_file_info[file][rule]:  # higher weight
                return False

    return True

def check_db(package_name: str, cursor: sqlite3.cursor): -> str
    """Check if the package has been scanned previously"""
    query = "SELECT FileData FROM Packages where PackageName = ?"

    cursor.execute(query, (package_name,))
    result = cursor.fetchone()

    if result is None:
        return ""
    
    return result[0]
