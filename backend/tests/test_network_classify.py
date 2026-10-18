from app.network.classify import classify_endpoint, normalize_path

def test_normalize_path_redacts_ids_queries_uuid_and_truncates():
    assert normalize_path("http://host/api/messages/123?token=secret#frag")=="/api/messages/{id}"
    assert normalize_path("/sessions/550e8400-e29b-41d4-a716-446655440000/x") == "/sessions/{uuid}/x"
    assert len(normalize_path("/"+"a"*200))==120
    assert normalize_path(None)=="/"

def test_classifies_all_endpoint_classes():
    cases=[
      ("POST","/api/auth/register",None,"register"),("POST","/api/auth/login",None,"login"),
      ("POST","/api/auth/logout",None,"logout"),("GET","/api/auth/me",None,"me"),
      ("POST","/api/messages",None,"message_send"),("GET","/api/messages/{id}",None,"message_fetch"),
      ("POST","/api/messages/{id}/verification",None,"message_verify"),("POST","/api/baseline/messages",None,"baseline_send"),
      ("GET","/api/baseline/messages/{id}",None,"baseline_fetch"),("POST","/api/lab/text-metrics",None,"metrics_post"),
      ("GET","/api/dashboard/logs",None,"dashboard"),("POST","/api/admin/tamper",None,"admin"),
      ("GET","/api/health",None,"health"),("GET","/ws",None,"websocket_upgrade"),
      ("POST","/anything",101,"websocket_upgrade"),("GET","/assets/app.js",None,"static"),("POST","/unknown",None,"other")]
    for method,path,status,expected in cases:assert classify_endpoint(method,path,status)==expected
