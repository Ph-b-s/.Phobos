"""Scoped, bounded HTML reconnaissance crawler."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from models import Asset, AssetType, EndpointAsset, FormAsset, InputAsset
from request_manager import HTTPResponseData, RequestError, RequestManager
from graph import Graph

_SKIP={'mailto','tel','javascript','data','blob'}

def normalize_url(base_url:str, raw_url:str)->str|None:
    candidate=urljoin(base_url,raw_url.strip()); p=urlparse(candidate)
    if p.scheme.lower() not in {'http','https'} or not p.hostname: return None
    q=urlencode(sorted(parse_qsl(p.query,keep_blank_values=True)))
    return urlunparse((p.scheme.lower(),p.netloc.lower(),p.path or '/', '', q, ''))

@dataclass(slots=True)
class ParsedPage:
    links:set[str]=field(default_factory=set); scripts:set[str]=field(default_factory=set); forms:list[dict]=field(default_factory=list)

class _Parser(HTMLParser):
    def __init__(self,base_url): super().__init__(convert_charrefs=True); self.base_url=base_url; self.result=ParsedPage(); self._form=None
    def handle_starttag(self,tag,attrs):
        m={k.lower():v or '' for k,v in attrs}; tag=tag.lower()
        if tag=='a' and m.get('href'):
            raw=m['href']
            if urlparse(raw).scheme.lower() not in _SKIP:
                u=normalize_url(self.base_url,raw)
                if u:self.result.links.add(u)
        elif tag=='script' and m.get('src'):
            u=normalize_url(self.base_url,m['src'])
            if u:self.result.scripts.add(u)
        elif tag=='form':
            action=normalize_url(self.base_url,m.get('action') or self.base_url)
            self._form={'action':action or self.base_url,'method':(m.get('method') or 'GET').upper(),'inputs':[]}; self.result.forms.append(self._form)
        elif tag in {'input','textarea','select','button'} and self._form is not None:
            self._form['inputs'].append({'name':m.get('name',''),'type':m.get('type',tag)})
    def handle_endtag(self,tag):
        if tag.lower()=='form': self._form=None

@dataclass(frozen=True,slots=True)
class ReconResult:
    pages:tuple[Asset,...]; endpoints:tuple[EndpointAsset,...]; forms:tuple[FormAsset,...]; inputs:tuple[InputAsset,...]; javascript:tuple[Asset,...]; errors:tuple[str,...]
    @property
    def assets(self): return (*self.pages,*self.endpoints,*self.forms,*self.inputs,*self.javascript)

class ReconCrawler:
    def __init__(self,request_manager:RequestManager,*,max_pages:int=100):
        if max_pages<1: raise ValueError('max_pages must be at least 1')
        self.request_manager=request_manager; self.max_pages=max_pages
    def crawl(self,target:str,*,graph:Graph|None=None)->ReconResult:
        queue=deque([normalize_url(target,target) or target]); visited=set(); seen_ep=set(); seen_js=set(); seen_q=set(); counters={k:0 for k in ('page','endpoint','form','input','javascript')}; pages=[]; endpoints=[]; forms=[]; inputs=[]; js=[]; errors=[]
        while queue and len(visited)<self.max_pages:
            url=queue.popleft()
            if url in visited or not self.request_manager.scope.is_in_scope(url): continue
            visited.add(url)
            try: response=self.request_manager.get(url)
            except RequestError as exc: errors.append(f'{url}: {exc}'); continue
            ctype=response.headers.get('content-type','').lower()
            if 'text/html' not in ctype and 'application/xhtml+xml' not in ctype: continue
            counters['page']+=1; page=Asset(f"page_{counters['page']:04d}",AssetType.PAGE,response.url,response.url,1.0,{'status_code':response.status,'content_type':ctype}); pages.append(page)
            if graph: graph.add_node(id=page.id,type=page.type.value,label=page.name,attributes=page.metadata)
            p=_Parser(response.url)
            try: p.feed(response.text); p.close()
            except Exception as exc: errors.append(f'{response.url}: parser error: {exc}'); continue
            for link in sorted(p.result.links):
                if not self.request_manager.scope.is_in_scope(link): continue
                if link not in visited: queue.append(link)
                if link not in seen_ep:
                    seen_ep.add(link); counters['endpoint']+=1; ep=EndpointAsset(f"endpoint_{counters['endpoint']:04d}",AssetType.ENDPOINT,link,link,0.95,{},'GET',None); endpoints.append(ep)
                    if graph: graph.add_node(id=ep.id,type=ep.type.value,label=ep.name); graph.add_edge(source=page.id,target=ep.id,relationship='links_to')
                    for name,_ in parse_qsl(urlparse(link).query,keep_blank_values=True):
                        key=(link,name)
                        if not name or key in seen_q: continue
                        seen_q.add(key); counters['input']+=1; ia=InputAsset(f"input_{counters['input']:04d}",AssetType.INPUT,name,link,1.0,{'source_endpoint':link,'source_page':response.url},'query','query','GET'); inputs.append(ia)
                        if graph: graph.add_node(id=ia.id,type=ia.type.value,label=ia.name,attributes=ia.metadata); graph.add_edge(source=ep.id,target=ia.id,relationship='accepts')
            for script in sorted(p.result.scripts):
                if not self.request_manager.scope.is_in_scope(script) or script in seen_js: continue
                seen_js.add(script); counters['javascript']+=1; a=Asset(f"javascript_{counters['javascript']:04d}",AssetType.JAVASCRIPT,script,script,0.98,{'source_page':response.url}); js.append(a)
                if graph: graph.add_node(id=a.id,type=a.type.value,label=a.name,attributes=a.metadata); graph.add_edge(source=page.id,target=a.id,relationship='loads')
            for idx,fd in enumerate(p.result.forms,1):
                if not self.request_manager.scope.is_in_scope(fd['action']): continue
                counters['form']+=1; named=tuple(x['name'] for x in fd['inputs'] if x['name']); form=FormAsset(f"form_{counters['form']:04d}",AssetType.FORM,f"{response.url}#{idx}",fd['action'],1.0,{'source_page':response.url},fd['method'],named); forms.append(form)
                if graph: graph.add_node(id=form.id,type=form.type.value,label=form.name,attributes=form.metadata); graph.add_edge(source=page.id,target=form.id,relationship='contains')
                for item in fd['inputs']:
                    if not item['name']: continue
                    counters['input']+=1; ia=InputAsset(f"input_{counters['input']:04d}",AssetType.INPUT,item['name'],fd['action'],1.0,{'source_form':form.id,'source_page':response.url},item['type'] or 'text','form',fd['method']); inputs.append(ia)
                    if graph: graph.add_node(id=ia.id,type=ia.type.value,label=ia.name,attributes=ia.metadata); graph.add_edge(source=form.id,target=ia.id,relationship='accepts')
        return ReconResult(tuple(pages),tuple(endpoints),tuple(forms),tuple(inputs),tuple(js),tuple(errors))
