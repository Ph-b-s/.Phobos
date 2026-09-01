"""Single outbound HTTP boundary with scope-aware redirects and size limits."""
from __future__ import annotations
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener
from scope import ScopeError, ScopeValidator

class RequestError(RuntimeError): pass

class _NoRedirectHandler(HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers): return fp
    def http_error_302(self, req, fp, code, msg, headers): return fp
    def http_error_303(self, req, fp, code, msg, headers): return fp
    def http_error_307(self, req, fp, code, msg, headers): return fp
    def http_error_308(self, req, fp, code, msg, headers): return fp

@dataclass(frozen=True, slots=True)
class HTTPResponseData:
    url: str; status: int; headers: dict[str,str]; body: bytes
    @property
    def text(self) -> str:
        ctype=self.headers.get('content-type',''); charset='utf-8'
        marker='charset='
        if marker in ctype.lower(): charset=ctype.lower().split(marker,1)[1].split(';',1)[0].strip() or charset
        return self.body.decode(charset, errors='replace')

class RequestManager:
    def __init__(self, scope: ScopeValidator, *, timeout: float=10.0, max_redirects: int=5, user_agent: str='Phobos/0.1', max_response_bytes: int=2_000_000):
        self.scope=scope; self.timeout=timeout; self.max_redirects=max_redirects; self.user_agent=user_agent; self.max_response_bytes=max_response_bytes
        self._opener=build_opener(_NoRedirectHandler())
    def get(self, url: str, *, headers: dict[str,str]|None=None) -> HTTPResponseData: return self.request('GET',url,headers=headers)
    def request(self, method: str, url: str, *, headers: dict[str,str]|None=None, body: bytes|None=None) -> HTTPResponseData:
        current=self._validate(url); merged={'User-Agent':self.user_agent,'Accept':'*/*'}; merged.update(headers or {})
        for count in range(self.max_redirects+1):
            req=Request(current,data=body,method=method.upper(),headers=merged)
            try: response=self._opener.open(req,timeout=self.timeout)
            except HTTPError as exc: response=exc
            except URLError as exc: raise RequestError(f'request failed for {current}: {exc.reason}') from exc
            except TimeoutError as exc: raise RequestError(f'request timed out for {current}') from exc
            status=getattr(response,'status',response.getcode()); final=self._validate(response.geturl()); location=response.headers.get('Location')
            if location and status in {301,302,303,307,308}:
                if count >= self.max_redirects: raise RequestError(f'maximum redirects exceeded for {url}')
                current=self._validate(urljoin(final,location))
                if status==303 or (status in {301,302} and method.upper()=='POST'): method='GET'; body=None
                continue
            return HTTPResponseData(final,status,{k.lower():v for k,v in response.headers.items()},self._read_limited(response))
        raise RequestError(f'maximum redirects exceeded for {url}')
    def _validate(self,url:str)->str:
        try: return self.scope.validate(url)
        except ScopeError as exc: raise RequestError(str(exc)) from exc
    def _read_limited(self,response)->bytes:
        length=response.headers.get('Content-Length')
        if length and length.isdigit() and int(length)>self.max_response_bytes: raise RequestError('response exceeds configured size limit')
        chunks=[]; remaining=self.max_response_bytes
        while remaining:
            chunk=response.read(min(65536,remaining))
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        if remaining==0 and response.read(1): raise RequestError('response exceeds configured size limit')
        return b''.join(chunks)
