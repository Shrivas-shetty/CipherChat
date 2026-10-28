from app.network.scanner import StreamScanner

JWT=b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
def test_marker_jwt_password_splits_retransmission_privacy_and_tail():
    s=StreamScanner("SECRETWORD123")
    s.feed((1,"c2s"),b'xx SECRETWORD123 yy "password":"not-stored" '+JWT[:18],1)
    s.feed((1,"c2s"),JWT[18:],2)
    before=s.result();s.feed((1,"c2s"),JWT[18:],3,True)
    assert before==s.result()
    result=s.result();assert result["marker"]["count"]==1 and result["marker"]["frames"]==[1]
    assert result["jwt"]["count"]==1 and result["password_field"]["count"]==1
    assert result["marker"]["snippet"] and len(result["marker"]["snippet"])<=120
    assert JWT.decode() not in repr(result) and "not-stored" not in repr(result)
    assert result["jwt"]["snippet"] is None and result["password_field"]["snippet"] is None

def test_marker_split_sanitized_tail_bounded_and_streams_isolated():
    s=StreamScanner("SECRETWORD123")
    s.feed((1,"c2s"),b"x"*600+b"SECRET",1)
    s.feed((1,"c2s"),b"WORD123"+bytes([0xff]),2)
    s.feed((2,"c2s"),b"WORD123",3)
    s.feed((1,"s2c"),b"WORD123",4)
    assert s.result()["marker"]["count"]==1
    assert len(s.result()["marker"]["snippet"])<=120
    assert "." in s.result()["marker"]["snippet"]
    assert max(s.tail_lengths.values())<=512
