import dynamiq
from dynamiq.mcp_server import InteractiveAnalysisMcpServer


def test_dynamiq_alias_exports_analysis_session() -> None:
    assert hasattr(dynamiq, "AnalysisSession")


def test_dynamiq_mcp_server_alias_import() -> None:
    assert InteractiveAnalysisMcpServer is not None
