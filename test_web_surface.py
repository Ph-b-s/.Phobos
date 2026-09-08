from web_surface import discover_api_endpoints


def test_discovers_fetch_and_method_routes() -> None:
    source = """
    <script>
      fetch('/api/search?q=test');
      fetch('/graphql');
      axios.post('/api/orders');
      GET('/health');
    </script>
    """
    result = discover_api_endpoints("https://example.com/app", source)
    keys = {(item.method, item.url) for item in result}

    assert ("GET", "https://example.com/api/search?q=test") in keys
    assert ("GET", "https://example.com/graphql") in keys
    assert ("POST", "https://example.com/api/orders") in keys
    assert ("GET", "https://example.com/health") in keys


def test_does_not_emit_non_http_or_fragment_routes() -> None:
    source = """
    fetch('#local');
    fetch('javascript:alert(1)');
    fetch('data:text/plain,hello');
    """
    assert discover_api_endpoints("https://example.com/app", source) == ()


def test_deduplicates_evidence_for_same_endpoint() -> None:
    source = "fetch('/api/items'); axios.get('/api/items');"
    result = discover_api_endpoints("https://example.com/", source)
    matches = [item for item in result if item.url == "https://example.com/api/items"]

    assert len(matches) == 1
    assert matches[0].method == "GET"
    assert len(matches[0].evidence) == 2
