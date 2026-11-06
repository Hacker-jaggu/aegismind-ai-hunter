from aegismind.report import to_sarif

def test_sarif_contains_rule_and_evidence():
    report={"version":"0.2.0","scope":{"start_url":"https://example.com"},"findings":[{
      "id":"HEADER-CSP","title":"CSP missing","severity":"LOW","status":"CONFIRMED","confidence":"HIGH",
      "url":"https://example.com/","why_it_matters":"Browser policy absent","remediation":"Add CSP",
      "category":"A05","impact_limitations":"Not exploit proof","evidence":{"missing_header":"content-security-policy"},
      "verification_layers":["L1","L2"]}]}
    sarif=to_sarif(report)
    assert sarif["version"]=="2.1.0"
    assert sarif["runs"][0]["results"][0]["properties"]["status"]=="CONFIRMED"
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"]=="HEADER-CSP"
