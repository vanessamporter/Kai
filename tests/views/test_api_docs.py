def test_api_docs_page(client, db):
    response = client.get("/api/docs")
    assert response.status_code == 200
    content = response.content.decode()
    assert "swagger-ui" in content
    assert "openapi.yaml" in content
    assert "validatorUrl: null" in content


def test_license_page(client):
    response = client.get("/LICENSE")
    assert response.status_code == 200
    assert b"GNU AFFERO GENERAL PUBLIC LICENSE" in response.content


def test_source_link(client, settings):
    settings.SOURCE_CODE_URL = "https://example.com/kai"
    response = client.get("/login")
    assert b'href="https://example.com/kai"' in response.content
