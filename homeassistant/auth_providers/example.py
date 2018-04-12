from collections import OrderedDict

import voluptuous as vol

from homeassistant import auth, data_entry_flow


USER_SCHEMA = vol.Schema({
    vol.Required('username'): str,
    vol.Required('password'): str,
})


CONFIG_SCHEMA = auth.AUTH_PROVIDER_SCHEMA.extend({
    vol.Required('users'): [USER_SCHEMA]
})


@auth.AUTH_PROVIDERS.register('example')
class ExampleAuthProvider(auth.AuthProvider):
    """Example auth provider based on hardcoded usernames and passwords."""

    async def async_credential_flow(self):
        """Return a flow to login."""
        schema = OrderedDict()
        schema['username'] = str
        schema['password'] = str
        return data_entry_flow.SingleSchemaFlow(vol.Schema(schema))

    async def async_get_or_create_credentials(self, flow_result):
        """Get credentials based on the flow result."""
        username = flow_result['username']

        user = next((user for user in self.config['users']
                     if user['username'] == username), None)

        if user is None:
            raise auth.InvalidUser

        if user['password'] != flow_result['password']:
            raise auth.InvalidPassword

        for credential in await self.async_credentials():
            if credential.data['username'] == username:
                return credential

        # Create new credentials.
        return self.async_create_credentials({
            'username': username
        })
