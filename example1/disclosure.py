class VulnerabilityDisclosure:
    """Process for reporting found vulnerabilities"""
    
    def report_vulnerability(self, finding: Dict):
        """Proper vulnerability reporting"""
        report_template = {
            "title": "Security Vulnerability Report",
            "sections": [
                {
                    "name": "Description",
                    "content": finding.get("description", "")
                },
                {
                    "name": "Impact",
                    "content": finding.get("impact", "")
                },
                {
                    "name": "Steps to Reproduce",
                    "content": finding.get("steps", [])
                },
                {
                    "name": "Suggested Fix",
                    "content": finding.get("fix", "")
                },
                {
                    "name": "Proof of Concept",
                    "content": "Available upon request"
                }
            ],
            "contact": {
                "security_team": "security@example.com",
                "pgp_key": "Available on security page"
            },
            "metadata": {
                "disclosure_date": time.time() + 90*24*60*60,  # 90 days
                "public": False
            }
        }
        return report_template