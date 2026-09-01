"""Safe filesystem storage for scan artifacts and evidence."""
from __future__ import annotations
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

class EvidenceStore:
    def __init__(self, root: Path | str='.phobos'):
        self.root=Path(root)
        self.evidence_dir=self.root/'evidence'
    def initialize(self): self.evidence_dir.mkdir(parents=True,exist_ok=True)
    def write_json(self,name:str,payload:Any)->Path:
        if not name or Path(name).is_absolute(): raise ValueError('artifact name must be relative')
        destination=(self.root/name).resolve(); root=self.root.resolve()
        if destination!=root and root not in destination.parents: raise ValueError('artifact must stay inside the evidence store')
        if destination.suffix.lower()!='.json': raise ValueError('EvidenceStore only writes JSON artifacts')
        destination.parent.mkdir(parents=True,exist_ok=True)
        tmp=destination.with_name(destination.name+'.tmp')
        tmp.write_text(json.dumps(self._serialize(payload),indent=2,ensure_ascii=False,sort_keys=True)+'\n',encoding='utf-8')
        tmp.replace(destination); return destination
    def write_evidence(self,evidence_id:str,payload:Any)->Path:
        if not evidence_id or Path(evidence_id).name!=evidence_id or evidence_id in {'.','..'}: raise ValueError('evidence_id must be a simple filename-safe identifier')
        return self.write_json(f'evidence/{evidence_id}.json',payload)
    @staticmethod
    def _serialize(value:Any)->Any:
        if hasattr(value,'to_dict'): return EvidenceStore._serialize(value.to_dict())
        if is_dataclass(value): return EvidenceStore._serialize(asdict(value))
        if isinstance(value,dict): return {str(k):EvidenceStore._serialize(v) for k,v in value.items()}
        if isinstance(value,(list,tuple)): return [EvidenceStore._serialize(v) for v in value]
        if isinstance(value,Path): return str(value)
        if hasattr(value,'value'): return value.value
        return value
