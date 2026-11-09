"""Páginas do dashboard e o perfil mínimo de cada uma."""

from app.schemas.user import role_at_least

# (ficheiro, título, ícone, perfil mínimo). A API aplica as mesmas regras nas rotas.
PAGES = [
    ("app_pages/history.py", "Histórico", ":material/monitoring:", "leitor"),
    ("app_pages/submit.py", "Submeter incidente", ":material/add_alert:", "analista"),
    ("app_pages/users.py", "Utilizadores", ":material/group:", "admin"),
]


def pages_for_role(role: str) -> list[tuple[str, str, str]]:
    return [
        (path, title, icon) for path, title, icon, minimum in PAGES if role_at_least(role, minimum)
    ]
