from datetime import timedelta

import pytest
from sqlmodel import Session, select

from app.api.auth import INVALID_LOGIN, LOCKED_LOGIN
from app.cli import main as cli
from app.core import security
from app.db.models import UserModel, UserSessionModel, utcnow
from app.services import auth_service

PASSWORD = "palavra-passe-forte"


def make_user(engine, username, role, password=PASSWORD):
    with Session(engine) as db:
        return auth_service.create_user(db, username, password, role).id


@pytest.fixture
def anon(client):
    """O mesmo cliente, mas sem a chave de serviço: só entra quem fizer login."""
    client.headers.pop("X-API-Key", None)
    return client


def login(anon, username, password=PASSWORD):
    return anon.post("/auth/login", json={"username": username, "password": password})


def bearer(anon, username, password=PASSWORD) -> dict:
    response = login(anon, username, password)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


# --- Login ------------------------------------------------------------------------------------


def test_login_with_right_password_opens_session(anon, engine):
    make_user(engine, "ana", "analista")

    response = login(anon, "ana")

    assert response.status_code == 200
    body = response.json()
    assert (body["username"], body["role"]) == ("ana", "analista")
    me = anon.get("/auth/me", headers={"Authorization": f"Bearer {body['token']}"})
    assert me.json() == {"username": "ana", "role": "analista"}


def test_username_is_case_insensitive(anon, engine):
    make_user(engine, "Ana", "leitor")

    assert login(anon, "  ANA ").status_code == 200


def test_wrong_password_and_unknown_user_get_the_same_answer(anon, engine):
    make_user(engine, "ana", "analista")

    wrong = login(anon, "ana", "palavra-passe-errada")
    unknown = login(anon, "ninguem", "palavra-passe-errada")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": INVALID_LOGIN}


def test_inactive_user_cannot_log_in(anon, engine):
    user_id = make_user(engine, "ana", "analista")
    with Session(engine) as db:
        auth_service.update_user(db, db.get(UserModel, user_id), is_active=False)

    assert login(anon, "ana").json() == {"detail": INVALID_LOGIN}


def test_password_is_stored_only_as_argon2_hash(engine):
    user_id = make_user(engine, "ana", "leitor")

    with Session(engine) as db:
        stored = db.get(UserModel, user_id).password_hash
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


# --- Bloqueio por tentativas ------------------------------------------------------------------


def test_too_many_failures_lock_the_username_even_with_right_password(anon, engine):
    make_user(engine, "ana", "analista")
    for _ in range(5):
        assert login(anon, "ana", "errada-errada").status_code == 401

    locked = login(anon, "ana")

    assert locked.status_code == 429
    assert locked.json() == {"detail": LOCKED_LOGIN}


def test_unknown_username_is_locked_the_same_way(anon):
    for _ in range(5):
        login(anon, "ninguem", "errada-errada")

    assert login(anon, "ninguem", "errada-errada").json() == {"detail": LOCKED_LOGIN}


def test_lock_ends_after_the_lock_time(engine):
    make_user(engine, "ana", "analista")
    start = utcnow()
    with Session(engine) as db:
        for _ in range(5):
            auth_service.authenticate(db, "ana", "errada-errada", now=start)
        with pytest.raises(auth_service.LoginLockedError):
            auth_service.authenticate(db, "ana", PASSWORD, now=start + timedelta(minutes=14))

        user = auth_service.authenticate(db, "ana", PASSWORD, now=start + timedelta(minutes=16))

        assert user is not None and user.username == "ana"


def test_successful_login_resets_the_failure_count(anon, engine):
    make_user(engine, "ana", "analista")
    for _ in range(4):
        login(anon, "ana", "errada-errada")
    assert login(anon, "ana").status_code == 200

    for _ in range(4):
        login(anon, "ana", "errada-errada")
    assert login(anon, "ana").status_code == 200


# --- Sessões ----------------------------------------------------------------------------------


def test_requests_without_session_are_rejected(anon):
    assert anon.get("/threats/").status_code == 401
    assert anon.get("/threats/", headers={"Authorization": "Bearer inventado"}).status_code == 401


def test_expired_session_is_rejected(anon, engine):
    user_id = make_user(engine, "ana", "analista")
    with Session(engine) as db:
        old = auth_service.create_session(
            db, db.get(UserModel, user_id), now=utcnow() - timedelta(days=1)
        )

    response = anon.get("/threats/", headers={"Authorization": f"Bearer {old.token}"})

    assert response.status_code == 401


def test_logout_invalidates_the_token(anon, engine):
    make_user(engine, "ana", "analista")
    headers = bearer(anon, "ana")

    assert anon.post("/auth/logout", headers=headers).status_code == 204
    assert anon.get("/threats/", headers=headers).status_code == 401


@pytest.mark.parametrize("change", [{"is_active": False}, {"password": "outra-palavra-passe"}])
def test_deactivation_or_password_change_ends_sessions(anon, engine, change):
    make_user(engine, "admin", "admin")
    user_id = make_user(engine, "ana", "analista")
    ana = bearer(anon, "ana")

    response = anon.patch(f"/users/{user_id}", json=change, headers=bearer(anon, "admin"))

    assert response.status_code == 200
    assert anon.get("/threats/", headers=ana).status_code == 401


def test_session_token_is_not_stored_in_clear(anon, engine):
    make_user(engine, "ana", "analista")
    token = login(anon, "ana").json()["token"]

    with Session(engine) as db:
        stored = db.exec(select(UserSessionModel.token_hash)).all()
    assert token not in stored


def test_cleanup_removes_expired_sessions(engine):
    user_id = make_user(engine, "ana", "analista")
    with Session(engine) as db:
        user = db.get(UserModel, user_id)
        auth_service.create_session(db, user, now=utcnow() - timedelta(days=1))
        auth_service.create_session(db, user)

        auth_service.cleanup(db)

        assert len(db.exec(select(UserSessionModel)).all()) == 1


# --- Perfis -----------------------------------------------------------------------------------

# (método, caminho, corpo, perfil mínimo). As respostas 404/409 contam como "deixou passar".
ROUTES = [
    ("GET", "/threats/", None, "leitor"),
    ("GET", "/threats/blocked", None, "leitor"),
    ("GET", "/threats/999", None, "leitor"),
    (
        "POST",
        "/threats/analyze",
        {"ip_address": "10.0.0.1", "threat_type": "DDoS", "description": "x"},
        "analista",
    ),
    ("POST", "/threats/block", {"ip_address": "10.0.0.1"}, "analista"),
    ("DELETE", "/threats/block/10.0.0.99", None, "admin"),
    ("GET", "/users/", None, "admin"),
    ("POST", "/users/", {"username": "novo", "password": PASSWORD, "role": "leitor"}, "admin"),
    ("PATCH", "/users/999", {"role": "leitor"}, "admin"),
]
ALLOWED = {
    "leitor": {"leitor"},
    "analista": {"leitor", "analista"},
    "admin": {"leitor", "analista", "admin"},
}


@pytest.mark.parametrize("role", ["leitor", "analista", "admin"])
@pytest.mark.parametrize("method,path,body,minimum", ROUTES, ids=[f"{r[0]} {r[1]}" for r in ROUTES])
def test_each_role_reaches_only_what_it_may(anon, engine, role, method, path, body, minimum):
    make_user(engine, "pessoa", role)
    headers = bearer(anon, "pessoa")

    response = anon.request(method, path, json=body, headers=headers)

    if minimum in ALLOWED[role]:
        assert response.status_code not in (401, 403), response.text
    else:
        assert response.status_code == 403


@pytest.mark.parametrize("method,path,body,minimum", ROUTES, ids=[f"{r[0]} {r[1]}" for r in ROUTES])
def test_every_protected_route_needs_a_session(anon, method, path, body, minimum):
    assert anon.request(method, path, json=body).status_code == 401


def test_public_routes_stay_public(anon):
    assert anon.get("/").status_code == 200


# --- Chave de serviço -------------------------------------------------------------------------


def test_service_key_has_full_access(client):
    assert client.get("/users/").status_code == 200


def test_service_key_can_be_disabled(client, monkeypatch):
    monkeypatch.setattr(security.settings, "API_KEY", "")

    assert client.get("/threats/").status_code == 401


# --- Gestão de utilizadores -------------------------------------------------------------------


def test_admin_creates_user_who_can_then_log_in(anon, engine):
    make_user(engine, "admin", "admin")

    created = anon.post(
        "/users/",
        json={"username": "joao", "password": PASSWORD, "role": "leitor"},
        headers=bearer(anon, "admin"),
    )

    assert created.status_code == 201
    assert "password" not in created.text and "hash" not in created.text
    assert login(anon, "joao").json()["role"] == "leitor"


@pytest.mark.parametrize(
    "body,status",
    [
        ({"username": "joao", "password": "curta", "role": "leitor"}, 422),
        ({"username": "jo", "password": PASSWORD, "role": "leitor"}, 422),
        ({"username": "joao", "password": PASSWORD, "role": "chefe"}, 422),
        ({"username": "admin", "password": PASSWORD, "role": "leitor"}, 409),
    ],
)
def test_invalid_new_users_are_rejected(anon, engine, body, status):
    make_user(engine, "admin", "admin")

    response = anon.post("/users/", json=body, headers=bearer(anon, "admin"))

    assert response.status_code == status


@pytest.mark.parametrize("change", [{"role": "analista"}, {"is_active": False}])
def test_last_active_admin_cannot_be_removed(anon, engine, change):
    admin_id = make_user(engine, "admin", "admin")

    response = anon.patch(f"/users/{admin_id}", json=change, headers=bearer(anon, "admin"))

    assert response.status_code == 409
    assert "último admin" in response.json()["detail"]


# --- Linha de comandos ------------------------------------------------------------------------


def answers(*values):
    pending = list(values)
    return lambda _prompt: pending.pop(0)


def test_cli_creates_admin_with_password_from_prompt(engine, capsys):
    code = cli(
        ["create-user", "Admin", "--role", "admin"], engine=engine, ask=answers(PASSWORD, PASSWORD)
    )

    assert code == 0
    assert "criado" in capsys.readouterr().out
    with Session(engine) as db:
        user = auth_service.get_user_by_name(db, "admin")
        assert user.role == "admin"
        assert auth_service.authenticate(db, "admin", PASSWORD) is not None


def test_cli_rejects_mismatched_or_short_passwords(engine):
    assert (
        cli(
            ["create-user", "ana", "--role", "admin"], engine=engine, ask=answers(PASSWORD, "outra")
        )
        == 1
    )
    assert (
        cli(["create-user", "ana", "--role", "admin"], engine=engine, ask=answers("curta", "curta"))
        == 1
    )
    with Session(engine) as db:
        assert auth_service.get_user_by_name(db, "ana") is None


def test_cli_set_password_replaces_it(engine):
    make_user(engine, "ana", "admin")

    code = cli(
        ["set-password", "ana"],
        engine=engine,
        ask=answers("nova-palavra-passe", "nova-palavra-passe"),
    )

    assert code == 0
    with Session(engine) as db:
        assert auth_service.authenticate(db, "ana", "nova-palavra-passe") is not None
