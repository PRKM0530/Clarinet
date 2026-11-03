"""
clarinet/cli.py  -  administration from the machine itself.

    python -m clarinet.cli reset-password USERNAME

Use this when the only administrator has forgotten their password. Whoever can run it already controls the
machine and the database, so it asks for no old password. It also clears a lockout and signs the account
out everywhere.
"""
import argparse
import getpass
import sys


def reset_password(username: str, password: str | None) -> int:
    from clarinet.auth import audit, end_sessions, hash_password
    from clarinet.database import Base, SessionLocal, engine
    from clarinet.models import Member

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        member = db.query(Member).filter(Member.username == username).first()
        if member is None:
            print(f"No account named {username!r}.", file=sys.stderr)
            return 1
        if password is None:
            password = getpass.getpass("New password (at least 8 characters): ")
            if password != getpass.getpass("Repeat it: "):
                print("The two passwords do not match.", file=sys.stderr)
                return 1
        if len(password) < 8:
            print("The password must be at least 8 characters.", file=sys.stderr)
            return 1
        member.password_hash = hash_password(password)
        member.failed_attempts, member.locked_until, member.is_active = 0, None, True
        from clarinet.models.reports import LoginAttempt
        db.query(LoginAttempt).filter(LoginAttempt.username == username, LoginAttempt.success == False).delete()  # noqa: E712
        # (the per-address lockout counts failed attempts, so clearing the account's own failures lifts it too)
        audit(db, None, "RESET_PASSWORD_CLI", "Member", member.member_id)
        end_sessions(db, member.member_id)
    print(f"Password for {username!r} changed. They can sign in now.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m clarinet.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    rp = sub.add_parser("reset-password", help="set a new password for an account")
    rp.add_argument("username")
    rp.add_argument("--password", help="the new password (otherwise you are asked for it)")
    args = parser.parse_args(argv)
    return reset_password(args.username, args.password)


if __name__ == "__main__":
    raise SystemExit(main())
