
from app.layers.layer2_waf.inspector import inspect_text


def test_detects_sql_injection():
    assert inspect_text(
        "id=1 UNION SELECT username FROM users"
    ) == "SQLI_UNION_SELECT"


def test_detects_xss_script():
    assert inspect_text(
        "<script>alert(1)</script>"
    ) == "XSS_SCRIPT"


def test_detects_path_traversal():
    assert inspect_text(
        "../../etc/passwd"
    ) == "PATH_TRAVERSAL"


def test_detects_url_encoded_attack():
    assert inspect_text(
        "%3Cscript%3Ealert(1)%3C/script%3E"
    ) == "XSS_SCRIPT"


def test_allows_normal_text():
    assert inspect_text(
        "Hello, this is a normal request"
    ) is None


def test_allows_empty_text():
    assert inspect_text("") is None
 
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.layers.layer2_waf.middleware import WAFMiddleware


def create_waf_test_client():
    async def homepage(request):
        return PlainTextResponse("Request allowed")

    app = Starlette(
        routes=[
            Route("/", homepage),
            Route("/health", homepage),
        ]
    )

    app.add_middleware(WAFMiddleware)
    return TestClient(app)


def test_middleware_blocks_xss_request():
    client = create_waf_test_client()

    response = client.get(
        "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
    )

    assert response.status_code == 403
    assert response.json()["error"] == "request_blocked"
    assert response.json()["rule"] == "XSS_SCRIPT"


def test_middleware_allows_normal_request():
    client = create_waf_test_client()

    response = client.get("/?q=hello")

    assert response.status_code == 200
    assert response.text == "Request allowed"


def test_health_path_is_excluded_from_waf():
    client = create_waf_test_client()

    response = client.get(
        "/health?q=%3Cscript%3Ealert(1)%3C/script%3E"
    )

    assert response.status_code == 200
