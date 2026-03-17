"""Config flow for Hikvision Doorbell."""

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN
from .isapi import HikvisionISAPIAuthError, HikvisionISAPIClient, HikvisionISAPIError

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("name", default="Doorbell"): str,
        vol.Required("host"): str,
        vol.Required("username", default="admin"): str,
        vol.Required("password"): str,
        vol.Optional("sdk_port", default=8000): int,
    }
)


class HikvisionDoorbellConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Hikvision Doorbell."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            client = HikvisionISAPIClient(
                host=user_input["host"],
                username=user_input["username"],
                password=user_input["password"],
            )
            try:
                device_info = await client.get_device_info()
            except HikvisionISAPIAuthError:
                errors["base"] = "invalid_auth"
            except HikvisionISAPIError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected exception during config flow")
                errors["base"] = "unknown"
            else:
                unique_id = device_info.get("serial") or user_input["host"]
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input["name"],
                    data=user_input,
                )
            finally:
                await client.close()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
