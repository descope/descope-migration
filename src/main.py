import argparse

from setup import setup_logging


def main():
    dry_run = False
    verbose = False
    with_passwords = False
    passwords_file_path = ""
    from_json = False
    json_file_path = ""

    # General Tool Flags
    parser = argparse.ArgumentParser(
        description="This program assists you in migrating your users and user groups from various services to Descope."
    )
    parser.add_argument(
        "provider",
        choices=["firebase", "auth0", "cognito", "ping"],
        help="Specify the service to migrate from",
    )
    parser.add_argument("--dry-run", action="store_true", help="Enable dry run mode")
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose printing for live runs and dry runs",
    )

    # Provider Specific Flags
    parser.add_argument(
        "--with-passwords",
        nargs=1,
        metavar="file-path",
        help="Run the script with passwords from the specified file",
    )
    parser.add_argument(
        "--from-json",
        nargs=1,
        metavar="file-path",
        help="Run the script with users from the specified file rather than API",
    )

    args = parser.parse_args()

    provider = args.provider
    # General Flags
    if args.dry_run:
        dry_run = True

    if args.verbose:
        verbose = True

    # Auth0 Flags
    if args.with_passwords:
        passwords_file_path = args.with_passwords[0]
        with_passwords = True
        # print(f"Running with passwords from file: {passwords_file_path}")

    if args.from_json:
        json_file_path = args.from_json[0]
        from_json = True

    setup_logging(provider)

    if provider == "firebase":
        from firebase_migration import migrate_firebase

        migrate_firebase(dry_run, verbose)
    elif provider == "auth0":
        from auth0_migration import migrate_auth0

        migrate_auth0(dry_run, verbose, passwords_file_path, json_file_path)
    elif provider == "cognito":
        from cognito_migration import migrate_cognito

        migrate_cognito(dry_run, verbose)
    elif provider == "ping":
        from ping_migration import migrate_pingone

        migrate_pingone(dry_run, verbose)
    else:
        print("Invalid service specified.")


if __name__ == "__main__":
    main()
