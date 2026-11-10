"""Offline check of the Frontegg migration against the documented Frontegg API response shapes.

Run: python -m unittest discover -s tests
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ.setdefault("DESCOPE_PROJECT_ID", "P" + "x" * 27)
os.environ.setdefault("DESCOPE_MANAGEMENT_KEY", "test")

import frontegg_migration as fm  # noqa: E402
from utils import decode_cert  # noqa: E402

PEM = "-----BEGIN CERTIFICATE-----\nMIIBAA==\n-----END CERTIFICATE-----"

PERMS = [
    {"id": "p1", "key": "docs.read", "name": "Read", "description": "", "fePermission": False},
    {"id": "p2", "key": "fe.secure.read", "name": "FE", "description": "", "fePermission": True},
    {"id": "p3", "key": "fe.unused", "name": "FE2", "description": "", "fePermission": True},
]
ROLES = [{"id": "r1", "key": "admin", "name": "Admin", "description": "", "tenantId": None, "permissions": ["p1", "p2"]}]
TENANT_PAGES = [
    {"items": [{"tenantId": "t1", "name": "Acme"}], "_metadata": {"totalItems": 2, "totalPages": 2}},
    {"items": [{"tenantId": "t2", "name": "Beta", "domain": "beta.com"}], "_metadata": {"totalItems": 2, "totalPages": 2}},
]
USERS = {
    "items": [
        {
            "id": "u1",
            "email": "a@acme.com",
            "name": "A",
            "phoneNumber": "-",
            "verified": True,
            "metadata": '{"x":1}',
            "isLocked": True,
            "tenants": [{"tenantId": "t1", "roles": []}],  # users v3 returns roles empty
        }
    ],
    "_metadata": {"totalItems": 1, "totalPages": 1},
}
SSO = [
    {
        "id": "c1",
        "enabled": True,
        "type": "saml",
        "ssoEndpoint": "https://acme.okta.com/app/acme_app/exk123/sso/saml",
        "publicCertificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJBQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=",
        "signRequest": True,
        "domains": [{"domain": "acme.com", "validated": True}],
        "roleIds": ["r1"],
    },
    {"id": "c2", "enabled": False, "type": "saml"},
]
GROUPS = [{"id": "g1", "group": "admins", "roleIds": ["r1"], "enabled": True}]


def fake_get(action, url, headers, **_):
    path = url.replace(fm.FRONTEGG_API_URL, "")
    resp = mock.Mock(status_code=200)
    if path.startswith("/tenants/resources/tenants/v2"):
        page = int(path.split("_offset=")[1])
        resp.json.return_value = TENANT_PAGES[page] if page < len(TENANT_PAGES) else {"items": []}
    elif path == "/identity/resources/permissions/v1":
        resp.json.return_value = PERMS
    elif path == "/identity/resources/roles/v1":
        resp.json.return_value = ROLES
    elif path.startswith("/identity/resources/users/v3/roles"):
        assert headers.get("frontegg-tenant-id") == "t1" and "ids=u1" in path
        resp.json.return_value = [{"tenantId": "t1", "userId": "u1", "roleIds": ["r1"]}]
    elif path.startswith("/identity/resources/users/v3"):
        resp.json.return_value = USERS
    elif path == "/team/resources/sso/v1/configurations":
        assert headers.get("frontegg-tenant-id") in ("t1", "t2")
        resp.json.return_value = SSO if headers["frontegg-tenant-id"] == "t1" else []
    elif path == "/team/resources/sso/v1/configurations/c1/groups":
        resp.json.return_value = GROUPS
    else:
        raise AssertionError(f"unexpected GET {path}")
    return resp


class FronteggMigrationTest(unittest.TestCase):
    def setUp(self):
        fm._access_token, fm._token_expiry = "tok", float("inf")
        fm._permission_id_to_name.clear()
        fm._role_id_to_name.clear()
        patcher = mock.patch.object(fm, "api_request_with_retry", side_effect=fake_get)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.descope = mock.MagicMock()
        self.descope.mgmt.user.invite_batch.return_value = {"createdUsers": [{}], "failedUsers": []}
        # t2 already exists in Descope with its own domain and settings
        self.descope.mgmt.tenant.create.side_effect = lambda name, id: (_ for _ in ()).throw(Exception("exists")) if id == "t2" else None
        self.descope.mgmt.tenant.load.return_value = {
            "name": "Beta (Descope)", "selfProvisioningDomains": ["old.com"], "enforceSSO": True, "customAttributes": {"a": 1},
        }
        p2 = mock.patch.object(fm, "descope_client", self.descope)
        p2.start()
        self.addCleanup(p2.stop)
        p3 = mock.patch.object(fm, "create_custom_attributes_in_descope")
        p3.start()
        self.addCleanup(p3.stop)

    def test_live_run(self):
        fm.migrate_frontegg(dry_run=False, verbose=False, with_sso=True)
        m = self.descope.mgmt

        # Both tenant pages fetched (page-number pagination)
        self.assertEqual(["t1", "t2"], [c.kwargs["id"] for c in m.tenant.create.call_args_list])

        # Built-in permission referenced by a role is created; unreferenced built-in is not
        self.assertEqual(["docs.read", "fe.secure.read"], [c.kwargs["name"] for c in m.permission.create.call_args_list])

        # Role created once, by key, with resolved permission names
        m.role.create.assert_called_once()
        self.assertEqual("admin", m.role.create.call_args.kwargs["name"])
        self.assertEqual(["docs.read", "fe.secure.read"], m.role.create.call_args.kwargs["permission_names"])

        # User carries its tenant + tenant role; invalid phone dropped
        (user,) = m.user.invite_batch.call_args.kwargs["users"]
        self.assertEqual("a@acme.com", user.login_id)
        self.assertIsNone(user.phone)
        self.assertEqual([("t1", ["admin"])], [(t.tenant_id, t.role_names) for t in user.user_tenants])
        self.assertEqual('{"x":1}', user.custom_attributes["metadata"])
        self.assertEqual("disabled", user.status)  # locked in Frontegg

        # Existing tenant keeps its name/settings and gets the Frontegg domain merged in
        upd = m.tenant.update.call_args.kwargs
        self.assertEqual(("t2", "Beta (Descope)", ["old.com", "beta.com"], True, {"a": 1}),
                         (upd["id"], upd["name"], upd["self_provisioning_domains"], upd["enforce_sso"], upd["custom_attributes"]))

        # Only the enabled SAML config is migrated, with derived entity ID, PEM cert and group mapping
        m.sso.configure_saml_settings.assert_called_once()
        kw = m.sso.configure_saml_settings.call_args.kwargs
        self.assertEqual("t1", kw["tenant_id"])
        self.assertEqual(["acme.com"], kw["domains"])
        s = kw["settings"]
        self.assertEqual("http://www.okta.com/exk123", s.idp_entity_id)
        self.assertEqual(PEM, s.idp_cert)
        self.assertEqual(["admin"], s.default_sso_roles)
        self.assertEqual("admins", s.role_mappings[0].groups[0])
        self.assertFalse(s.disable_sign_request)

    def test_dry_run_writes_nothing(self):
        fm.migrate_frontegg(dry_run=True, verbose=False, with_sso=True)
        self.descope.mgmt.tenant.create.assert_not_called()
        self.descope.mgmt.user.invite_batch.assert_not_called()
        self.descope.mgmt.sso.configure_saml_settings.assert_not_called()

    def test_decode_cert(self):
        self.assertEqual(PEM, decode_cert(PEM))
        self.assertEqual(PEM, decode_cert(SSO[0]["publicCertificate"]))
        self.assertEqual(PEM, decode_cert("MIIBAA=="))  # bare DER base64 gets PEM armor


if __name__ == "__main__":
    unittest.main()
