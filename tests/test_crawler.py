from aegismind.crawler import extract_links

def test_extracts_only_exact_host_safe_paths():
    html = '<a href="/about">A</a><a href="https://evil.test/x">B</a><a href="/logout">C</a><a href="/search?q=x">D</a><a href="javascript:alert(1)">E</a><a href="/docs#top">F</a>'
    assert extract_links("https://example.com/",html,{"example.com"}) == ["https://example.com/about","https://example.com/docs"]

def test_link_limit():
    html = ''.join(f'<a href="/p{i}">x</a>' for i in range(10))
    assert len(extract_links("https://example.com/",html,{"example.com"},limit=3)) == 3
