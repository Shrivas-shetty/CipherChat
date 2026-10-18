import re

JWT_RE=re.compile(rb"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
PASSWORD_RE=re.compile(rb'"password"\s*:\s*"')
PASSWORD_VALUE_RE=re.compile(rb'"password"\s*:\s*"[^"\\]*(?:\\.[^"\\]*)*"',re.I)

class StreamScanner:
    def __init__(self,marker: str|None=None):
        self.patterns={"jwt":JWT_RE,"password_field":PASSWORD_RE}
        if marker:self.patterns["marker"]=re.compile(re.escape(marker.encode("ascii")))
        self._tails={};self._offsets={};self._seen={};self._results={k:{"count":0,"frames":[],"snippet":None} for k in self.patterns}
    @property
    def tail_lengths(self):return {k:len(v) for k,v in self._tails.items()}
    def feed(self,stream_key,payload: bytes,frame_no: int,is_retransmission: bool=False):
        if is_retransmission or not payload:return self._results
        tail=self._tails.get(stream_key,b"");combined=tail+payload;boundary=len(tail)
        absolute_start=self._offsets.get(stream_key,0)-len(tail)
        for kind,pattern in self.patterns.items():
            seen=self._seen.setdefault((stream_key,kind),set())
            for match in pattern.finditer(combined):
                if match.end()<=boundary:continue
                match_start=absolute_start+match.start()
                if match_start in seen:continue
                seen.add(match_start)
                result=self._results[kind];result["count"]+=1
                if len(result["frames"])<10:result["frames"].append(frame_no)
                if kind=="marker" and result["snippet"] is None:
                    sample=combined[max(0,match.start()-40):min(len(combined),match.end()+40)]
                    sample=JWT_RE.sub(b"[jwt]",sample)
                    sample=PASSWORD_VALUE_RE.sub(b'"password":"[redacted]"',sample)
                    result["snippet"]="".join(chr(b) if 32<=b<=126 else "." for b in sample)[:120]
        self._offsets[stream_key]=self._offsets.get(stream_key,0)+len(payload)
        floor=self._offsets[stream_key]-512
        for key,seen in self._seen.items():
            if key[0]==stream_key:seen.intersection_update(x for x in seen if x>=floor)
        self._tails[stream_key]=combined[-512:]
        return self._results
    def result(self):return {k:{"count":v["count"],"frames":list(v["frames"]),"snippet":v["snippet"] if k=="marker" else None} for k,v in self._results.items()}
