"""Gerenciamento de usuários pela linha de comando.

    python -m app.cli create-user NOME --role admin
    python -m app.cli set-password NOME

A senha é pedida no terminal, sem eco, e nunca passa por argumentos, .env ou código.
No Docker:

    docker exec -it netsentinel-api python -m app.cli create-user admin --role admin
"""

import argparse
import getpass
import sys
from collections.abc import Callable

from sqlmodel import Session

from app.schemas.user import ROLES
from app.services.auth_service import UserError, create_user, get_user_by_name, update_user


def _ask_password(ask: Callable[[str], str]) -> str | None:
    password = ask("Senha: ")
    if password != ask("Repita a senha: "):
        print("As senhas não coincidem.", file=sys.stderr)
        return None
    return password


def main(argv: list[str] | None = None, engine=None, ask: Callable[[str], str] = getpass.getpass):
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Usuários")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create-user", help="cria um usuário")
    create.add_argument("username")
    create.add_argument("--role", choices=ROLES, required=True)

    reset = commands.add_parser("set-password", help="troca a senha e encerra as sessões")
    reset.add_argument("username")

    args = parser.parse_args(argv)
    if engine is None:
        from app.db.database import engine as default_engine

        engine = default_engine

    password = _ask_password(ask)
    if password is None:
        return 1

    with Session(engine) as db:
        try:
            if args.command == "create-user":
                user = create_user(db, args.username, password, args.role)
                print(f"Usuário {user.username} criado com o perfil {user.role}.")
            else:
                user = get_user_by_name(db, args.username)
                if user is None:
                    print("Usuário não encontrado.", file=sys.stderr)
                    return 1
                update_user(db, user, password=password)
                print(f"Senha de {user.username} alterada; as sessões foram encerradas.")
        except UserError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
