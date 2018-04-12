"""Provide an authentication layer for Home Assistant."""
import asyncio
import logging
import uuid

import attr
import voluptuous as vol
from voluptuous.humanize import humanize_error

from . import data_entry_flow
from .core import callback
from .const import CONF_TYPE, CONF_NAME, CONF_ID
from .exceptions import HomeAssistantError
from .util.decorator import Registry


_LOGGER = logging.getLogger(__name__)


AUTH_PROVIDERS = Registry()

AUTH_PROVIDER_SCHEMA = vol.Schema({
    vol.Required(CONF_TYPE): str,
    vol.Optional(CONF_NAME): str,
    # Specify ID if you have two auth providers for same type.
    vol.Optional(CONF_ID): str,
})


class AuthError(HomeAssistantError):
    """Generic authentication error."""


class InvalidUser(AuthError):
    """Raised when an invalid user has been specified."""


class InvalidPassword(AuthError):
    """Raised when an invalid password has been supplied."""


class UnknownError(AuthError):
    """When an unknown error occurs."""


class AuthProvider:
    """Provider of user authentication."""

    DEFAULT_TITLE = 'Unnamed auth provider'

    def __init__(self, store, config):
        """Initialize an auth provider."""
        self.store = store
        self.config = config

    @property
    def id(self):
        """Return id of the auth provider.

        Optional, can be None.
        """
        return self.config.get(CONF_ID)

    @property
    def type(self):
        """Return type of the provider."""
        return self.config[CONF_TYPE]

    @property
    def name(self):
        """Return the name of the auth provider."""
        return self.config.get(CONF_NAME, self.DEFAULT_TITLE)

    async def async_initialize(self):
        """Initialize the auth provider."""

    async def async_credentials(self):
        """Return the existing credentials of this provider."""
        return await self.store.credentials_for_provider(self.type, self.id)

    async def async_credential_flow(self):
        """Return the data flow for logging in with auth provider."""
        raise NotImplementedError

    async def async_get_or_create_credentials(self, flow_result):
        """Get credentials based on the flow result."""
        raise NotImplementedError

    @callback
    def async_create_credentials(self, data):
        """Create credentials."""
        return Credentials(
            auth_provider_type=self.type,
            auth_provider_id=self.id,
            data=data,
        )

    # async def async_register_flow(self):
    #     """Return the data flow for registering with the auth provider."""
    #     raise NotImplementedError

    # async def async_register(self, flow_result):
    #     """Create a new user and return credentials."""
    #     raise NotImplementedError

    # async def async_change_password(self, credentials, new_password):
    #     """Change the password of a user."""
    #     raise NotImplementedError


@attr.s(slots=True)
class User:
    """A user."""

    id = attr.ib(type=uuid.UUID)
    is_owner = attr.ib(type=bool)
    name = attr.ib(type=str)


@attr.s(slots=True)
class Credentials:
    """Credentials for a user on an auth provider."""

    auth_provider_type = attr.ib(type=str)
    auth_provider_id = attr.ib(type=str)

    # Allow the auth provider to store data to represent their auth.
    data = attr.ib(type=dict)

    id = attr.ib(type=uuid.UUID, default=None)
    user = attr.ib(type=User, default=None)


@attr.s(slots=True)
class Client:
    """Client that interacts with Home Assistant on behalf of a user."""

    id = attr.ib(type=uuid.UUID)
    secret = attr.ib(type=str)


@attr.s(slots=True)
class Token:
    """Token to access Home Assistant."""

    id = attr.ib(type=uuid.UUID)
    credentials = attr.ib(type=Credentials)
    user = attr.ib(type=User)
    access_token = attr.ib(type=str)
    refresh_token = attr.ib(type=str)


@callback
def load_auth_provider_module(provider):
    """Load an auth provider."""
    # Stub.
    from .auth_providers import example
    return example


async def auth_manager_from_config(provider_configs):
    """Initialize an auth manager from config."""
    store = AuthStore()
    providers = await asyncio.gather(auth_provider_from_config(config)
                                     for config in provider_configs)
    manager = AuthManager(providers)
    await manager.initialize()
    return manager


async def auth_provider_from_config(config):
    """Initialize an auth provider from a config."""
    provider_name = config[CONF_TYPE]
    module = load_auth_provider_module(provider_name)

    try:
        config = module.CONFIG_SCHEMA(config)
    except vol.Invalid as err:
        _LOGGER.error('Invalid configuration for auth provider %s: %s',
                      provider_name, humanize_error(config, err))
        return None

    return AUTH_PROVIDERS[provider_name](config)


class AuthManager:
    """Manage the authentication for Home Assistant."""

    def __init__(self, providers):
        """Initialize the auth manager."""
        self._providers = providers
        self.login_flow =

    async def initialize(self):
        """Initialize the auth manager."""
        await asyncio.wait(provider.async_initialize() for provider
                           in self._providers.values())

    async def async_auth_providers():
        """Return a list of available auth providers."""
        return [{
            'name': provider.name,
            'id': provider.id,
            'type': provider.type,
        } for provider in self._providers.values()]

    async def


class AuthStore:
    """Holds authentication info."""

    def __init__(self):
        self.credentials = []

    async def credentials_for_provider(self, provider_type, provider_id):
        """Return credentials for specific auth provider type and id."""
        return [credential for credential in self.credentials
                if credential.auth_provider_type == provider_type and
                credential.auth_provider_id == provider_id]

    async def async_load(self):
        pass

    async def async_save(self):
        pass
