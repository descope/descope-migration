# Descope Third-Party Migration Tool
This repository includes a Python utility for migrating from a third-party service to Descope.

This currently tool supports the following third-party services:
- Auth0
- AWS Cognito
- Firebase
- Ping
  

>Migrations can differ wildly depending on the specific identity implementation and provider. However, this tool serves as a template that you can edit if it doesn't fully meet your needs.

## Setup 💿

1. Clone the Repo:

```
git clone git@github.com:descope/descope-migration.git
```

2. Create a Virtual Environment

```
python3 -m venv venv
source venv/bin/activate
```

3. Install the Necessary Python libraries

```
pip3 install -r requirements.txt
```

4. Follow the guide for your specific third-party 
    - [Auth0](https://docs.descope.com/migrate/auth0)
    - [AWS Cognito](https://docs.descope.com/migrate/cognito)
    - [Firebase](https://docs.descope.com/migrate/firebase)
    - [Ping](https://docs.descope.com/migrate/ping)
    - If you're using a Custom data store please follow this guide instead [Custom Data Store](https://docs.descope.com/migrate/custom)

## Running the Migration Script 🚀

The tool will handle migrations differently for each third-party service. However, there are some general commands that remain consistent across all third parties.

### Third-Party Providers

To pick the the Third-Party service to migrate from you must pass the `provider` flag

The following are supported: 
- `auth0` for Auth0 by Okta
- `cognito` for AWS Cognito
- `firebase` for Firebase
- `ping` for Ping

Use:
```
python3 src/main.py auth0
```

#### Guides for each provider 

Pick the third-party you are migrating from and follow the corrosponding guide
- [Auth0](https://docs.descope.com/migrate/auth0)
- [AWS Cognito](https://docs.descope.com/migrate/cognito)
- [Firebase](https://docs.descope.com/migrate/firebase)
- [Ping](https://docs.descope.com/migrate/ping)

### Dry Run vs Live Run

If you want to see what users and other information will be migrated before actually migrating you can dry run the migration for all thrid-parties. Live run will actually perform the migration

#### Dry Run 

The `--dry-run` flag can be used by all third-parties:

```
python3 src/main.py provider --dry-run
```

#### Live Run 

To live run exclude the `--dry-run` flag:

```
python3 src/main.py provider 
```
### Verbose

You can add the `-v` or `--verbose` flag to any dry run or live run by any provider to get more information on which users or objects are being migrated.
Exclude the flag to get a more compact printout.

Use:
```
Dry Run Verbose: python3 src/main.py --dry-run -v
Live Run Verbose: python3 src/main.py -v
```
## Issue Reporting ⚠️

For any issues or suggestions, feel free to open an issue in the GitHub repository.

## License 📜

This project is licensed under the MIT License - see the LICENSE file for details.


