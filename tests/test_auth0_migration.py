"""Offline checks for the Auth0 SSO helpers. Run: python -m unittest discover -s tests"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ.setdefault("DESCOPE_PROJECT_ID", "P" + "x" * 27)
os.environ.setdefault("DESCOPE_MANAGEMENT_KEY", "test")

import auth0_migration as am  # noqa: E402


class Auth0SSOTest(unittest.TestCase):
    def test_add_sso_login_id_keeps_roles_and_tenants(self):
        client = mock.MagicMock()
        client.mgmt.user.load.return_value = {"user": {
            "loginIds": ["a@x.com"], "email": "a@x.com", "roleNames": ["admin"],
            "userTenants": [{"tenantId": "org_1", "roleNames": ["member"]}], "ssoAppIds": ["app1"],
        }}
        with mock.patch.object(am, "descope_client", client):
            ok, _ = am._add_sso_login_id("a@x.com", "00u1-org_1")
        self.assertTrue(ok)
        kw = client.mgmt.user.update.call_args.kwargs
        self.assertEqual(["00u1-org_1"], kw["additional_login_ids"])
        self.assertEqual(["admin"], kw["role_names"])
        self.assertEqual([("org_1", ["member"])], [(t.tenant_id, t.role_names) for t in kw["user_tenants"]])
        self.assertEqual(["app1"], kw["sso_app_ids"])

    def test_entity_id_only_derived_for_okta(self):
        self.assertEqual("http://www.okta.com/exk1", am._derive_idp_entity_id("https://a.okta.com/app/exk1/sso/saml/metadata"))
        self.assertEqual("", am._derive_idp_entity_id("https://login.microsoftonline.com/t/federationmetadata/2007-06/federationmetadata.xml"))


if __name__ == "__main__":
    unittest.main()
