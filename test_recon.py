from dataclasses import dataclass
from graph import Graph
from request_manager import HTTPResponseData
from scope import ScopeValidator
from crawler import ReconCrawler

@dataclass
class FakeRequestManager:
    scope: ScopeValidator
    pages: dict[str, HTTPResponseData]
    def get(self,url,*,headers=None): return self.pages[url]

def test_recon_discovers_core_assets():
    root='https://example.com/'; about='https://example.com/about'
    response=HTTPResponseData(root,200,{'content-type':'text/html; charset=utf-8'},b'<a href="/about?next=1">About</a><script src="/app.js"></script><form action="/comment" method="POST"><input name="comment" type="text"></form>')
    response_about=HTTPResponseData(about,200,{'content-type':'text/html'},b'<p>about</p>')
    m=FakeRequestManager(ScopeValidator(('example.com',),allow_private_targets=True),{root:response,'https://example.com/about?next=1':response_about})
    g=Graph(); r=ReconCrawler(m,max_pages=10).crawl(root,graph=g)
    assert len(r.pages)==2
    assert len(r.forms)==1
    assert len(r.inputs)==2
    assert len(r.javascript)==1
    assert any(e.url=='https://example.com/about?next=1' for e in r.endpoints)
    assert len(g.nodes)>0 and len(g.edges)>0
